FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-opensearch"]
COPY baton-opensearch /