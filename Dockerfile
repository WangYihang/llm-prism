FROM gcr.io/distroless/static:nonroot
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/llm-redactor /llm-redactor 
ENTRYPOINT ["/llm-redactor"]