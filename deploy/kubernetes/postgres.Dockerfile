# Pin the disposable conformance database while producing a single-platform
# image that kind can import without retaining a multi-architecture index.
FROM postgres:17@sha256:0af65001d05296a2ead57ac4a6412433d8913d1bb5d0c88435a7d1e1ee5cb04b
