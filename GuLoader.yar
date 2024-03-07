rule Potential_GuLoader {
   meta:
      description = "Detects GuLoader (vbs) samples which typically originate from a PDF or DOC contained within a password protected zip file, connecting to C2 (.png file hosted on server) and downloading the file content to VBS and PDF"
      author = "Jonathon Sweeney"
      reference = "DarkGate Research"
      date = "2023-12-20"

  strings:
    $1 = "\x0D\n'' SIG '' Begin signature block\x0D\n'"
    $2 = " = CreateObject("
    $3 = "\x0D\n'' SIG '' End signature block\x0D\n"
    $4 = "n error resume next"

  condition:
    all of them
}
