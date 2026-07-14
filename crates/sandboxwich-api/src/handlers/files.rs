use crate::auth::*;
use crate::db::*;
use crate::error::*;
use crate::handlers::commands::*;
use crate::rows::*;
use crate::state::*;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Multipart, Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use sandboxwich_core::*;
use serde_json::json;
use sqlx::AnyConnection;
use sqlx::Row;
use uuid::Uuid;

pub(crate) const ALLOWED_FILE_MIME_TYPES: &[&str] = &[
    "application/json",
    "application/octet-stream",
    "application/pdf",
    "image/jpeg",
    "image/png",
    "text/csv",
    "text/markdown",
    "text/plain",
    "text/x-python",
    "text/x-rust",
    "text/x-shellscript",
];

pub(crate) fn normalize_file_path(path: Option<String>) -> Result<String, ApiError> {
    let path = path
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty())
        .ok_or_else(|| ApiError::bad_request("file path is required"))?;
    if path.contains('\0') {
        return Err(ApiError::bad_request("file path cannot contain NUL"));
    }
    if path.len() > 1024 {
        return Err(ApiError::bad_request("file path is too long"));
    }
    Ok(path)
}

pub(crate) fn normalize_mime_type(mime_type: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(mime_type) = mime_type else {
        return Ok(Some("application/octet-stream".to_string()));
    };
    let mime_type = mime_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if mime_type.is_empty() {
        return Ok(Some("application/octet-stream".to_string()));
    }
    if mime_type.len() > 128 {
        return Err(ApiError::bad_request("mime_type is too long"));
    }
    Ok(Some(mime_type))
}

pub(crate) fn validate_file_mime_type(mime_type: Option<&str>) -> Result<(), ApiError> {
    let Some(mime_type) = mime_type else {
        return Ok(());
    };
    if ALLOWED_FILE_MIME_TYPES.contains(&mime_type) {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!(
            "unsupported mime_type {mime_type:?}"
        )))
    }
}

pub(crate) fn validate_file_size(size_bytes: u64) -> Result<(), ApiError> {
    if size_bytes > MAX_SANDBOX_FILE_BYTES {
        return Err(ApiError::bad_request(format!(
            "file exceeds maximum size of {MAX_SANDBOX_FILE_BYTES} bytes"
        )));
    }
    Ok(())
}

pub(crate) fn download_name(path: &str) -> String {
    path.rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("sandbox-file")
        .replace(['"', '\\'], "_")
}

pub(crate) async fn upload_file(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<Json<FileResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;

    let mut path = None;
    let mut mime_type = None;
    let mut content = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request(format!("invalid multipart upload: {error}")))?
    {
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "path" => {
                path = Some(field.text().await.map_err(|error| {
                    ApiError::bad_request(format!("invalid multipart path field: {error}"))
                })?);
            }
            "mime_type" => {
                mime_type = Some(field.text().await.map_err(|error| {
                    ApiError::bad_request(format!("invalid multipart mime_type field: {error}"))
                })?);
            }
            "file" | "content" => {
                if mime_type.is_none() {
                    mime_type = field.content_type().map(ToOwned::to_owned);
                }
                if path.is_none() {
                    path = field.file_name().map(ToOwned::to_owned);
                }
                content = Some(field.bytes().await.map_err(|error| {
                    ApiError::bad_request(format!("invalid multipart file field: {error}"))
                })?);
            }
            _ => {
                let _ = field.bytes().await;
            }
        }
    }

    let path = normalize_file_path(path)?;
    let content = content.ok_or_else(|| ApiError::bad_request("file part is required"))?;
    validate_file_size(content.len() as u64)?;
    let mime_type = normalize_mime_type(mime_type)?;
    validate_file_mime_type(mime_type.as_deref())?;
    let file =
        upsert_sandbox_file(&state.db, sandbox_id, &path, mime_type.as_deref(), &content).await?;
    insert_event(
        &state.db,
        sandbox_id,
        SandboxEventKind::FileUploaded,
        json!({
            "fileId": file.id,
            "path": file.path,
            "sizeBytes": file.size_bytes,
            "mimeType": file.mime_type
        }),
    )
    .await?;

    Ok(Json(FileResponse { ok: true, file }))
}

pub(crate) async fn list_files(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<ListFilesResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let files = list_sandbox_files(&state.db, sandbox_id).await?;
    Ok(Json(ListFilesResponse { ok: true, files }))
}

pub(crate) async fn download_file(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path((sandbox_id, file_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let stored = fetch_sandbox_file(&state.db, sandbox_id, FileId(file_id)).await?;
    let content_type = stored
        .file
        .mime_type
        .as_deref()
        .unwrap_or("application/octet-stream")
        .to_string();
    Ok((
        [
            (header::CONTENT_TYPE, content_type),
            (
                header::CONTENT_DISPOSITION,
                format!(
                    "attachment; filename=\"{}\"",
                    download_name(&stored.file.path)
                ),
            ),
            // The Content-Type above reflects the stored (client-supplied)
            // mime type. Without nosniff, a browser that ever renders this
            // response inline (rather than honoring the attachment
            // disposition) may sniff the body and execute it as HTML/script
            // regardless of the declared type.
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        ],
        Bytes::from(stored.content),
    )
        .into_response())
}

pub(crate) struct StoredSandboxFile {
    pub(crate) file: SandboxFile,
    pub(crate) content: Vec<u8>,
}

pub(crate) async fn upsert_sandbox_file(
    db: &Database,
    sandbox_id: SandboxId,
    path: &str,
    mime_type: Option<&str>,
    content: &[u8],
) -> Result<SandboxFile, ApiError> {
    let mut tx = db.pool.begin().await?;
    let upserted = async {
        let now = Utc::now();
        let existing_id = fetch_sandbox_file_id_by_path_on_connection(
            db,
            &mut tx,
            sandbox_id,
            path,
        )
        .await?;
        let file_id = existing_id.unwrap_or_else(FileId::new);
        let content_base64 = general_purpose::STANDARD.encode(content);
        let size_bytes = i64::try_from(content.len())
            .map_err(|_| ApiError::bad_request("file is too large"))?;
        if existing_id.is_some() {
            let sql = format!(
                "update sandbox_files
                 set size_bytes = {}, mime_type = {}, content_base64 = {}, updated_at = {}
                 where id = {}",
                db.placeholder(1),
                db.placeholder(2),
                db.placeholder(3),
                db.placeholder(4),
                db.placeholder(5)
            );
            sqlx::query(&sql)
                .bind(size_bytes)
                .bind(mime_type)
                .bind(content_base64)
                .bind(now.to_rfc3339())
                .bind(file_id.to_string())
                .execute(&mut *tx)
                .await?;
        } else {
            let sql = format!(
                "insert into sandbox_files
                 (id, sandbox_id, path, size_bytes, mime_type, content_base64, created_at, updated_at)
                 values ({})",
                db.placeholders(8)
            );
            sqlx::query(&sql)
                .bind(file_id.to_string())
                .bind(sandbox_id.to_string())
                .bind(path)
                .bind(size_bytes)
                .bind(mime_type)
                .bind(content_base64)
                .bind(now.to_rfc3339())
                .bind(now.to_rfc3339())
                .execute(&mut *tx)
                .await?;
        }
        fetch_sandbox_file_metadata_on_connection(db, &mut tx, sandbox_id, file_id).await
    }
    .await;
    match upserted {
        Ok(file) => {
            tx.commit().await?;
            Ok(file)
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back sandbox file upsert");
            }
            Err(error)
        }
    }
}

pub(crate) async fn fetch_sandbox_file_id_by_path_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    path: &str,
) -> Result<Option<FileId>, ApiError> {
    let sql = format!(
        "select id from sandbox_files where sandbox_id = {} and path = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(path)
        .fetch_optional(&mut *connection)
        .await?;
    row.map(|row| {
        let id: String = row.try_get("id")?;
        Ok(FileId(parse_uuid(&id)?))
    })
    .transpose()
}

pub(crate) async fn list_sandbox_files(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Vec<SandboxFile>, ApiError> {
    let sql = format!(
        "select id, sandbox_id, path, size_bytes, mime_type, created_at, updated_at
         from sandbox_files
         where sandbox_id = {}
         order by path asc, id asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&db.pool)
        .await?;
    rows.into_iter().map(row_to_sandbox_file).collect()
}

pub(crate) async fn fetch_sandbox_file(
    db: &Database,
    sandbox_id: SandboxId,
    file_id: FileId,
) -> Result<StoredSandboxFile, ApiError> {
    let sql = format!(
        "select id, sandbox_id, path, size_bytes, mime_type, content_base64, created_at, updated_at
         from sandbox_files
         where sandbox_id = {} and id = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(file_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("file not found"))?;
    row_to_stored_sandbox_file(row)
}

pub(crate) async fn delete_sandbox_file_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    file_id: FileId,
) -> Result<(), ApiError> {
    let sql = format!(
        "delete from sandbox_files where sandbox_id = {} and id = {}",
        db.placeholder(1),
        db.placeholder(2),
    );
    let result = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(file_id.to_string())
        .execute(connection)
        .await?;
    if result.rows_affected() != 1 {
        return Err(ApiError::not_found("sandbox file not found"));
    }
    Ok(())
}

pub(crate) async fn delete_sandbox_file_if_present_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    file_id: FileId,
) -> Result<(), ApiError> {
    let sql = format!(
        "delete from sandbox_files where sandbox_id = {} and id = {}",
        db.placeholder(1),
        db.placeholder(2),
    );
    sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(file_id.to_string())
        .execute(connection)
        .await?;
    Ok(())
}

pub(crate) async fn fetch_sandbox_file_metadata_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    file_id: FileId,
) -> Result<SandboxFile, ApiError> {
    let sql = format!(
        "select id, sandbox_id, path, size_bytes, mime_type, created_at, updated_at
         from sandbox_files
         where sandbox_id = {} and id = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(file_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("file not found"))?;
    row_to_sandbox_file(row)
}
