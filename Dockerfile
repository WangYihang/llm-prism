FROM gcr.io/distroless/static:nonroot
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/llm-prism /llm-prism 
ENTRYPOINT ["/llm-prism"]