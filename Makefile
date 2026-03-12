.PHONY: demo-server demo-record demo

# Run the mock provider server
demo-server:
	go run demo/mock_server.go

# Record the demo (requires VHS and ffmpeg)
demo-record:
	vhs < demo/demo.tape

# Full demo workflow (you'll need to run demo-server in a separate terminal)
demo:
	@echo "1. Run 'make demo-server' in a separate terminal."
	@echo "2. Once server is up, run 'make demo-record' to generate demo.gif."

# Clean up temporary logs
clean-logs:
	rm -f llm-redactor.jsonl llm-redactor-detections.jsonl
