package com.internal.kpodmetrics.bpf

sealed class BpfException @JvmOverloads constructor(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

class BpfLoadException @JvmOverloads constructor(message: String, cause: Throwable? = null) :
    BpfException(message, cause)

class BpfMapException @JvmOverloads constructor(message: String, cause: Throwable? = null) :
    BpfException(message, cause)

class BpfHandleException(message: String) :
    BpfException(message)
