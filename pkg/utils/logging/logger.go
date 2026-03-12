package logging

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

func init() {
	zerolog.TimeFieldFormat = time.RFC3339Nano
}

type Loggers struct {
	System     zerolog.Logger
	SystemFile zerolog.Logger
	Traffic    zerolog.Logger
	Detection  zerolog.Logger
}

func New(appLogFile, trafficLogFile, detectionLogFile string) *Loggers {
	openFile := func(path string) *os.File {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			// Fallback to stderr if we can't open a log file
			return nil
		}
		return f
	}

	appFile := openFile(appLogFile)
	trafficFile := openFile(trafficLogFile)
	detectionFile := openFile(detectionLogFile)

	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: "15:04:05",
	}

	var appWriter io.Writer
	var appFileWriter io.Writer
	if appFile != nil {
		appWriter = zerolog.MultiLevelWriter(consoleWriter, appFile)
		appFileWriter = appFile
	} else {
		appWriter = consoleWriter
		appFileWriter = io.Discard
	}

	sysLog := zerolog.New(appWriter).
		Level(zerolog.InfoLevel).
		With().
		Timestamp().
		Logger()

	sysFileLog := zerolog.New(appFileWriter).
		Level(zerolog.DebugLevel).
		With().
		Timestamp().
		Logger()

	if trafficFile == nil {
		trafficFile = os.Stderr
	}
	if detectionFile == nil {
		detectionFile = os.Stderr
	}

	trafficLog := zerolog.New(trafficFile).
		With().
		Timestamp().
		Logger()

	detectionLog := zerolog.New(detectionFile).
		With().
		Timestamp().
		Logger()

	return &Loggers{
		System:     sysLog,
		SystemFile: sysFileLog,
		Traffic:    trafficLog,
		Detection:  detectionLog,
	}
}
