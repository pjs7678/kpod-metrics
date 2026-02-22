package com.internal.kpodmetrics.bpf

sealed class BpfException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

class BpfLoadException(message: String, cause: Throwable? = null) :
    BpfException(message, cause)

class BpfMapException(message: String, cause: Throwable? = null) :
    BpfException(message, cause)

class BpfHandleException(message: String) :
    BpfException(message)
