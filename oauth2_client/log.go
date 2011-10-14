package oauth2_client

import (
    "log"
)

func LogDebug(value ...interface{}) {
    if EnableLogDebug {
        log.Print(value)
    }
}

func LogDebugf(format string, value ...interface{}) {
    if EnableLogDebug {
        log.Printf(format, value)
    }
}

func LogInfo(value ...interface{}) {
    if EnableLogInfo {
        log.Print(value)
    }
}

func LogInfof(format string, value ...interface{}) {
    if EnableLogInfo {
        log.Printf(format, value)
    }
}

func LogError(value ...interface{}) {
    if EnableLogError {
        log.Print(value)
    }
}

func LogErrorf(format string, value ...interface{}) {
    if EnableLogError {
        log.Printf(format, value)
    }
}
