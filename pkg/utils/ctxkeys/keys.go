package ctxkeys

type ContextKey string

const (
	RequestID ContextKey = "request_id"
	Source    ContextKey = "source"
	Host      ContextKey = "host"
	Path      ContextKey = "path"
	Method    ContextKey = "method"
	ResponseWriter ContextKey = "response_writer"
)

// GetString safely extracts a string value from context
func GetString(ctx interface{ Value(any) any }, key ContextKey) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(key).(string); ok {
		return v
	}
	return ""
}
