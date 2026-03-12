package config

type CLI struct {
	LogFile          string `help:"Log file" env:"LLM_PRISM_LOG_FILE" default:"llm-prism.jsonl"`
	DetectionLogFile string `help:"Detection log file" env:"LLM_PRISM_DETECTION_LOG_FILE" default:"llm-prism-detections.jsonl"`
	RedactorRules    string `help:"Redactor rules file (TOML or JSON)" env:"LLM_PRISM_REDACTOR_RULES" default:"redactor_rules.toml"`
	Run              struct {
		ApiURL   string `help:"API URL" env:"LLM_PRISM_API_URL" default:"https://api.deepseek.com/anthropic"`
		ApiKey   string `help:"API Key" env:"LLM_PRISM_API_KEY" required:""`
		Provider string `help:"Provider" env:"LLM_PRISM_PROVIDER" default:"deepseek" enum:"deepseek,kimi"`
		Host     string `help:"Host" env:"LLM_PRISM_HOST" default:"0.0.0.0"`
		Port     int    `help:"Port" env:"LLM_PRISM_PORT" default:"4000"`
	} `cmd:"" help:"Run proxy"`
	Exec struct {
		ApiURL   string   `help:"API URL" env:"LLM_PRISM_API_URL" default:"https://api.deepseek.com/anthropic"`
		ApiKey   string   `help:"API Key" env:"LLM_PRISM_API_KEY" required:""`
		Provider string   `help:"Provider" env:"LLM_PRISM_PROVIDER" default:"deepseek" enum:"deepseek,kimi"`
		Host     string   `help:"Host" env:"LLM_PRISM_HOST" default:"127.0.0.1"`
		Port     int      `help:"Port" env:"LLM_PRISM_PORT" default:"4000"`
		Command  []string `arg:"" help:"Command to execute"`
	} `cmd:"" help:"Execute a command through the proxy"`
	Sync struct {
		URL string `help:"Gitleaks rules URL" default:"https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"`
	} `cmd:"" help:"Sync rules from Gitleaks official repository"`
	Version struct{} `cmd:"" help:"Version"`
}
