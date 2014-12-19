Imports System.Net
Imports System.Net.Sockets
Imports System.Text


Public Class clsRTMPSock

    'based on info available at
    ' * http://osflash.org/
    ' * http://wiki.gnashdev.org/
    ' * and my network card and wireshark 
    ' * by Michael Evanchik late nights

    Public Connection As New clsConnectionSettings

    Private m_sck As Socket
    Private m_sHost As String
    Private m_nPort As Integer = 1935

    Private m_nBuffSize As Integer = (64 * 1024)
    Private m_bBuff(m_nBuffSize) As Byte
    Private m_sBuff As String = vbNullString

    'persistant protocol values
    Private m_clsObjects(&HB) As clsRTMPObject
    Private m_nShakeSize As Integer = 0
    Private m_bFlag As Boolean = False
    Private m_bComplexObject As Boolean = False
    Private m_sConnectData As String = vbNullString

    Private Const HANDSHAKE_SIZE = 1536

    Public Enum SODataTypes
        Connect = &H1
        Disconnect = &H2
        SetAttribute = &H3
        UpdateData = &H4
        UpdateAttribute = &H5
        SendMessage = &H6
        Status = &H7
        ClearData = &H8
        DeleteData = &H9
        DeleteAttribute = &HA
        InitialData = &HB
    End Enum

    Public Enum RMTPDatatype
        ChunkSize = &H1             'changes the chunk size for packets
        Unknown1 = &H2              'anyone know this one?
        BytesRead = &H3             'send every x bytes read by both sides
        Ping = &H4                  'ping is a stream control message, has subtypes
        ServerBW = &H5              'the servers downstream bw
        ClientBW = &H6              'the clients upstream bw
        Unknown2 = &H7              'anyone know this one?
        AudioData = &H8             'packet containing audio
        VideoData = &H9             'packet containing video data
        '0x0A - 0xE : Unknown : anyone know?
        FlexStream = &HF            'Stream with variable length
        FlexSharedObject = &H10     'Shared object with variable length
        FlexMessage = &H11          'Shared message with variable length
        Notify = &H12               'an invoke which does not expect a reply
        SharedObject = &H13         'has subtypes
        Invoke = &H14               'like remoting call, used for stream actions too.

        FMS3 = &H16                 'FLV data
        'Set of one or more FLV tags, as documented on the Flash Video (FLV) page. Each 
        'tag will have an 11 byte header - [1 byte Type][3 bytes Size]
        '[3 bytes Timestamp][1 byte timestamp extention][3 bytes streamID], followed by 
        'the body, followed by a 4 byte footer containing the size of the body.
    End Enum

    'from amf0 spec @ http://download.macromedia.com/pub/labs/amf/amf0_spec_121207.pdf
    Public Enum TypeMarker
        TNumber = &H0
        TBoolean = &H1
        TString = &H2
        TObject = &H3
        TMovieclip = &H4
        TNull = &H5
        TUndefined = &H6
        TReference = &H7
        TEcmaarray = &H8
        TObjectend = &H9
        TStrictArray = &HA
        TDate = &HB
        TLongString = &HC
        TUnsupported = &HD
        TRecordset = &HE
        TXMLDocument = &HF
        TTypedObject = &H10
    End Enum

    Public Event Invoke(ByVal invoke As String, ByVal invokeid As Long, ByVal nullbyte As Byte, ByVal data As String)
    Public Event SharedObject(ByVal objname As String, ByVal objdata As String)
    Public Event Connected(ByVal established As Boolean)
    Public Event Disconnected()
    Public Event SockError(ByVal ex As SocketException)

    Private Sub DecodeField(ByRef objectdata As String, Optional ByVal dent As Integer = 0)

        Dim value As Object = Nothing
        Dim marker As TypeMarker
        Dim fname As String = vbNullString

        Dim types() As String = _
            { _
                "TNumber", _
                "TBoolean", _
                "TString", _
                "TObject", _
                "TMovieclip", _
                "TNull", _
                "TUndefined", _
                "TReference", _
                "TEcmaarray", _
                "TObjectend", _
                "TStrictArray", _
                "TDate", _
                "TLongString", _
                "TUnsupported", _
                "TRecordset", _
                "TXMLDocument", _
                "TTypedObject" _
            }

        objectdata = Chr(2) & objectdata
        AMFDecode(objectdata, marker, fname, False)
        If Left(objectdata, 1) = Chr(3) Then
            Debug.Print(Space(dent) & "SetField(TypeMarker.TObject, """ & fname & """, _")
            AMFDecode(objectdata, marker, value, False, (dent + 4))
            Debug.Print(Space(dent) & "    ) & _")
        Else
            AMFDecode(objectdata, marker, value, False, dent)
            If marker = TypeMarker.TString Then value = """" & value & """"
            Debug.Print(Space(dent) & "SetField(TypeMarker." & types(marker) & ", """ & fname & """, " & value & ") & _")
        End If

    End Sub

    Private Sub DecodeFields(ByVal objectdata As String, Optional ByVal dbg As Boolean = True, Optional ByVal dent As Integer = 0)

        'Debug.Print("decoding fields...")
        'Debug.Print(HexDump(objectdata))
        Do Until (objectdata = Chr(0) & Chr(0) & Chr(9)) Or (objectdata = Chr(0) & Chr(0) & Chr(0) & Chr(1) & Chr(0) & Chr(0) & Chr(0) & Chr(0))
            'Debug.Print(HexDump(objectdata))
            DecodeField(objectdata, dent)
            If Len(objectdata) = 0 Then Exit Do
        Loop

    End Sub

    Public Sub DecodePacket(ByVal packet As String)

        Dim marker As Integer
        Dim fval As Object = Nothing

        Dim i As Integer

        'Debug.Print("[*] decoding " & Len(packet) & " byte packet...")
        'Debug.Print(HexDump(packet))
        For i = 1 To 20
            If Not AMFDecode(packet, marker, fval) Then Exit For
        Next

    End Sub

    Property Host() As String
        Get
            Host = m_sHost
        End Get
        Set(ByVal value As String)
            m_sHost = value
        End Set
    End Property

    Property Port() As Integer
        Get
            Port = m_nPort
        End Get
        Set(ByVal value As Integer)
            m_nPort = value
        End Set
    End Property

    Private Function Int24(ByVal b1 As Byte, ByVal b2 As Byte, ByVal b3 As Byte) As Integer

        Return _
            b1 * (256 ^ 2) + _
            b2 * (256 ^ 1) + _
            b3 * (256 ^ 0)

    End Function

    Public Sub ProcessPacket(ByVal data As String)

        Dim marker As Byte
        Dim objid As Integer
        Dim headsz As Integer
        Dim packet As String = vbNullString
        Dim header As Byte()

        Static async As Boolean

        Do While async = True
            'Debug.Write(".")
            System.Threading.Thread.Sleep(100)
        Loop

        async = True
        m_sBuff &= data
        'Debug.Print("buffsz=" & Len(m_sBuff))

        Do
            If Len(m_sBuff) = 0 Then Exit Do
            marker = Asc(Left(m_sBuff, 1))
            objid = (marker And &H1F)

            If objid > UBound(m_clsObjects) Then
                'Debug.Print("[!] out of band message!")
                m_sBuff = vbNullString
                Exit Do
            End If
            With m_clsObjects(objid)
                Select Case (marker And &HC0)   'first 2 bits / header size
                    Case &H0  '00000000	- 12 bytes
                        headsz = 12
                        If Len(m_sBuff) >= headsz Then
                            header = Encoding.Default.GetBytes(Left(m_sBuff, headsz))
                            .m_nTimeStamp = Int24(header(1), header(2), header(3))
                            .m_nPacketSize = Int24(header(4), header(5), header(6))
                            .m_bRTMPDataType = header(7)
                            .m_nStreamId = BitConverter.ToInt32(header, 8)
                        End If

                    Case &H40 '01000000	- 8 bytes
                        headsz = 8
                        If Len(m_sBuff) >= headsz Then
                            header = Encoding.Default.GetBytes(Left(m_sBuff, headsz))
                            .m_nTimeStamp = Int24(header(1), header(2), header(3))
                            .m_nPacketSize = Int24(header(4), header(5), header(6))
                            .m_bRTMPDataType = header(7)
                        End If

                    Case &H80 '10000000	- 4 bytes
                        headsz = 4
                        If Len(m_sBuff) >= headsz Then
                            header = Encoding.Default.GetBytes(Left(m_sBuff, headsz))
                            .m_nTimeStamp = Int24(header(1), header(2), header(3))
                        End If

                    Case &HC0 '11000000	- 1 byte
                        headsz = 1
                        If Len(m_sBuff) >= headsz Then header = Encoding.Default.GetBytes(Left(m_sBuff, headsz))

                End Select

                'Debug.Print("")
                'Debug.Print("[+] object id: " & objid)
                'Debug.Print("[+] header sz: " & headsz)
                'Debug.Print("[+] time stmp: " & .m_nTimeStamp)
                'Debug.Print("[+] packet sz: " & .m_nPacketSize)
                'Debug.Print("[+] data type: " & .m_bRTMPDataType)
                'Debug.Print("[+] stream id: " & .m_nStreamId)

                If Len(m_sBuff) Then
                    'Debug.Print("packet.. (" & Len(m_sBuff) & ").")

                    ''------------------------------
                    If Not GetPacket(m_clsObjects(objid), objid, headsz, Len(data), m_sBuff, packet) Then
                        'Debug.Print("[!] incomplete packet, waiting!")
                        Exit Do
                    End If
                    ''------------------------------

                    If objid = 2 Then
                        'Debug.Print(HexDump(packet))
                    End If
                    If objid = 3 Or objid = 4 Then
                        Select Case .m_bRTMPDataType
                            Case RMTPDatatype.SharedObject
                                Dim objname As String = GetField(packet)
                                Dim objdata As String = packet

                                RaiseEvent SharedObject(objname, objdata)

                            Case RMTPDatatype.Invoke
                                Dim invoke As Object = Nothing
                                Dim invokeid As Object = Nothing
                                Dim nullbyte As Object = Nothing

                                DecodePacket(packet)

                                'Debug.Print("---8<---")
                                'Debug.Print("~> " & HexDump(Left(packet, 24)))
                                AMFDecode(packet, marker, invoke, False)
                                AMFDecode(packet, marker, invokeid, False)
                                AMFDecode(packet, marker, nullbyte, False)
                                RaiseEvent Invoke(CStr(invoke), CLng(invokeid), CByte(nullbyte), packet)

                                Select Case CStr(invoke)
                                    Case "close"
                                        'm_sck.Close()
                                        CloseSocket(True)
                                    Case "_result"
                                        If invokeid = 61503 Then
                                            'SendPacket(objid, RMTPDatatype.Invoke, _
                                            '        AMFEncode(TypeMarker.TString, "SettingsGetPropertyList") & _
                                            '        AMFEncode(TypeMarker.TNumber, 0) & _
                                            '        AMFEncode(TypeMarker.TNull, 0) & _
                                            '        AMFEncode(TypeMarker.TUndefined, 0) & _
                                            '        AMFEncode(TypeMarker.TUndefined, 0) & _
                                            '        AMFEncode(TypeMarker.TUndefined, 0) & _
                                            '        AMFEncode(TypeMarker.TUndefined, 0) _
                                            '    )

                                            'SendPacket(objid, RMTPDatatype.Invoke, _
                                            '        AMFEncode(TypeMarker.TString, "Login") & _
                                            '        AMFEncode(TypeMarker.TNumber, 0) & _
                                            '        AMFEncode(TypeMarker.TNull, 0) & _
                                            '        AMFEncode( _
                                            '              TypeMarker.TObject, _
                                            '              SetField(TypeMarker.TString, "password", "[INTEGRATED_MODE]") & _
                                            '              SetField(TypeMarker.TString, "name", "thiswonthurt") & _
                                            '              SetField(TypeMarker.TString, "gender", "Male") & _
                                            '              SetField(TypeMarker.TString, "level", "regular") & _
                                            '              SetField(TypeMarker.TString, "photo", "http://rudester.com/uploads_user/51000/50096/0_9308.jpg") & _
                                            '              SetField(TypeMarker.TString, "photoModeImage", "http://rudester.com/uploads_user/51000/50096/0_9308.jpg") _
                                            '          ) & _
                                            '        AMFEncode(TypeMarker.TUndefined, 0) & _
                                            '        AMFEncode(TypeMarker.TUndefined, 0) & _
                                            '        AMFEncode(TypeMarker.TUndefined, 0) _
                                            '    )
                                        End If

                                End Select
                            Case Else
                        End Select
                    End If
                Else
                    Exit Do
                End If
            End With
        Loop
        async = False

    End Sub

    Sub New()

        m_sck = New Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        NewObjects()

    End Sub

    Private Function ChompBytes(ByRef data As String, ByVal size As Integer) As String

        Dim read As String = vbNullString

        If size <= Len(data) Then
            read = Left(data, size)
            data = Mid(data, size + 1)
        End If

        Return read

    End Function

    Public Sub CloseSocket(Optional ByVal doevent As Boolean = True)

        If m_sck Is Nothing Then
            Debug.Print("[?] why am i closing nothing!?")
            Exit Sub
        End If

        Try
            m_sck.Shutdown(SocketShutdown.Both)
        Catch sckex As SocketException
            RaiseEvent SockError(sckex)
            sckex = Nothing
        Catch ex As Exception
            Debug.Print("[!] closeSocket : " & ex.ToString.ToLower)
        End Try

        Try
            m_sck.Disconnect(True)
        Catch sckex As SocketException
            RaiseEvent SockError(sckex)
            sckex = Nothing
        Catch ex As Exception
            Debug.Print("[!] closeSocket : " & ex.ToString.ToLower)
        End Try

        Debug.Print("[.] socket closed")
        If doevent Then RaiseEvent Disconnected()

    End Sub

    Overridable Sub Connect(Optional ByVal host As String = vbNullString, Optional ByVal port As Integer = -1)

        If Len(host) > 0 Then m_sHost = host
        If port >= 0 Then m_nPort = port

        m_sBuff = vbNullString
        m_nShakeSize = 0
        m_bFlag = False
        Try
            Dim ar As System.IAsyncResult
            Debug.Print("[>] connecting socket... state = " & m_sck.Connected)
            ar = m_sck.BeginConnect(m_sHost, m_nPort, AddressOf onConnect, m_sck)
            'With ar
            '    Debug.Print("-")
            '    Debug.Print("AsyncState:                " & .AsyncState.ToString)
            '    Debug.Print("AsyncWaitHandle:           " & .AsyncWaitHandle.ToString)
            '    Debug.Print("CompletedSynchronously:    " & .CompletedSynchronously.ToString)
            '    Debug.Print("IsCompleted:               " & .IsCompleted.ToString)
            'End With
        Catch ex As Exception
            Debug.Print("[!] connect : " & ex.ToString.ToLower)
        End Try

    End Sub

    Public Property ConnectData() As String
        Get
            ConnectData = m_sConnectData
        End Get
        Set(ByVal data As String)
            m_sConnectData = data
        End Set
    End Property

    Private Sub NewObjects()

        Dim i As Integer

        For i = 0 To UBound(m_clsObjects)
            m_clsObjects(i) = New clsRTMPObject
        Next

    End Sub

    Private Sub onConnect(ByVal ar As IAsyncResult)

        If Not ar.IsCompleted Then
            Debug.Print("[!] onConnect : asynch call not completed")
        End If
        Try
            'm_sck.EndConnect(ar)
            CType(ar.AsyncState, Socket).EndConnect(ar)
            RaiseEvent Connected(m_sck.Connected)
            If m_sck.Connected Then
                m_sck.BeginReceive(m_bBuff, 0, m_nBuffSize, SocketFlags.None, AddressOf onDataArrival, m_sck)
                Debug.Print("[*] established connection with rtmp server [" & m_sHost & ":" & m_nPort & "].")
                'Authenticate()
                SendHandshake()
            Else
                Debug.Print("[!] non-connect.")
            End If
        Catch sckex As SocketException
            RaiseEvent SockError(sckex)
            sckex = Nothing
        Catch ex As Exception
            Debug.Print("[!] connect(ex) : " & ex.ToString.ToLower)
            CloseSocket(False)
            'RaiseEvent SignOff()
        End Try

    End Sub

    Private Sub onDataArrival(ByVal ar As IAsyncResult)

        Dim read As Integer
        Dim data As String

        If m_sck Is Nothing Then Return
        If Not ar.IsCompleted Then
            Debug.Print("[!] onDataArrival : asynch call not completed")
        End If
        If (m_sck.Connected) Then
            Try
                read = m_sck.EndReceive(ar)
            Catch ex As Exception
                Debug.Print("[!] " & ex.ToString.ToLower)
                CloseSocket()
            End Try
            If read Then
                data = Encoding.Default.GetString(m_bBuff).Substring(0, read)
                'try catch connection faultz
                Try
                    m_sck.BeginReceive(m_bBuff, 0, m_nBuffSize, SocketFlags.None, AddressOf onDataArrival, m_sck)
                Catch ex As Exception
                    Debug.Print("[!] " & ex.ToString.ToLower)
                    CloseSocket()
                End Try
                'Debug.Print("[*] nomnomnom...")
                'Debug.Print("[+] size: " & Len(data) & ", buffer: " & Len(m_sBuff))

                If m_bFlag = False Then
                    'Debug.Print(HexDump(data))
                    'size+=len(data), chkif size = (2*handshakesize + 1) then send
                    m_nShakeSize += Len(data)
                    If m_nShakeSize >= ((2 * HANDSHAKE_SIZE) + 1) Then
                        SendConnect()
                        m_bFlag = True
                    End If
                Else
                    'Debug.Print(HexDump(data))
                    ProcessPacket(data)
                End If
            Else
                'Debug.Print("endgame :(")
                'CloseSocket(True)
                'RaiseEvent SignOff()
            End If
        Else
            Debug.Print("[!] end game (read)...")
            'm_sck.Close()
            'CloseSocket(True)
            'RaiseEvent SignOff()
        End If

    End Sub

    Private Sub onSend(ByVal ar As IAsyncResult)

        If Not ar.IsCompleted Then
            Debug.Print("[!] onSend : asynch call not completed")
        End If
        m_sck.EndSend(ar)
        Debug.Print("im in your .base RTMPing your doodz...")

    End Sub

    Public Function GetField(ByRef data As String) As String

        If Len(data) < 2 Then Return vbNullString

        Dim ssz() As Byte = Encoding.Default.GetBytes(StrReverse(Left(data, 2)))
        Dim nsz As Integer = BitConverter.ToUInt16(ssz, 0)

        If Len(data) < (2 + nsz) Then Return vbNullString
        ChompBytes(data, 2)

        Return ChompBytes(data, nsz)

    End Function

    Private Function GetPacket(ByVal rtmpobj As clsRTMPObject, ByVal objid As Integer, ByVal headsz As Integer, ByVal fb As Integer, ByVal buffer As String, ByRef packet As String) As Boolean

        Dim cchr As String
        Dim packdata As String
        Dim packsz As Integer = 0

        With rtmpobj

            m_bComplexObject = False
            Dim readsz As Integer = .m_nPacketSize

            If headsz = 4 Then
                'readsz = fb - headsz
                'Debug.Print("--4")
            End If

            If Len(buffer) < headsz Then Return False
            ChompBytes(buffer, headsz)
            packsz += headsz
            packdata = vbNullString
            'Debug.Write("[+] eating continue markers")
            Do While readsz > &H80
                'If (.m_nPacketSize > 128) And (.m_bRTMPDataType = RMTPDatatype.SharedObject) And (objid = 4) Then
                If (.m_bRTMPDataType = RMTPDatatype.SharedObject) Then
                    If (Asc(Left(buffer, 1)) And &HF0) > 0 Then
                        If (packsz = headsz) Or m_bComplexObject Then
                            m_bComplexObject = True
                            Debug.Write("[" & Left(HexDump(Left(buffer, 4)), 11) & "]")
                            If Len(buffer) < 4 Then Return False
                            ChompBytes(buffer, 4)
                            packsz += 4
                        End If
                    End If
                End If
                'Debug.Print(HexDump(m_sBuff))
                If Len(buffer) < &H80 Then Return False
                packdata &= ChompBytes(buffer, &H80)
                packsz += &H80

                If Len(buffer) < 1 Then Return False
                cchr = ChompBytes(buffer, 1)
                'Debug.Write("." & Hex(Asc(cchr)))
                Select Case (Asc(cchr) And &HF0)
                    Case &HC0
                        'Debug.Print("[+] continue => 0x" & Hex(Asc(ChompBytes(m_sBuff, 1))))
                    Case Else
                        'Debug.Print("")
                        'Debug.Print("[?] is this a valid c-chr? " & Asc(cchr))
                        m_sBuff = vbNullString
                        Return False
                End Select
                packsz += 1
                readsz -= &H80
            Loop
            'Debug.WriteLine("")

            If m_bComplexObject Or ((Asc(Left(buffer, 1)) And &HF0) > 0 And (.m_bRTMPDataType = RMTPDatatype.SharedObject) And (.m_nPacketSize <= 128)) Then
                If Len(buffer) < 4 Then Return False
                ChompBytes(buffer, 4)
                packsz += 4
            End If

            If Len(buffer) < readsz Then Return False
            packdata &= ChompBytes(buffer, readsz)
            packsz += readsz

        End With

        'gotta chomp packsz from m_sBuff
        ChompBytes(m_sBuff, packsz)
        packet = packdata
        Return True

    End Function

    Public Function SetField(ByVal marker As TypeMarker, ByVal fname As String, ByVal fval As String) As String
        'amf field, rename

        Dim svar As String

        svar = Chr(Len(fname) \ 256) & Chr(Len(fname) Mod 256)
        svar &= fname

        svar &= AMFEncode(marker, fval)
        '2byte len

        Return svar

    End Function

    Public Function AMFDecode(ByRef data As String, ByRef marker As TypeMarker, ByRef fval As Object, Optional ByVal dbg As Boolean = True, Optional ByVal dent As Integer = 0) As Boolean

        Dim size As Integer

        '====
        dbg = False
        '====
        If Len(data) = 0 Then Return False

        Try
            marker = Asc(Left(data, 1))
            Select Case marker
                Case TypeMarker.TNumber
                    'Debug.Print(Len(data))
                    If Len(data) < 9 Then Return False
                    fval = BitConverter.ToInt64(Encoding.Default.GetBytes(Mid(data, 2, 8)), 0)
                    'if (dbg) then Debug.Print("[.] int: " & fval)
                    If (dbg) Then Debug.Print("AMFEncode(TypeMarker.TNumber, " & fval & ") & _")
                    ChompBytes(data, 9)
                    Return True

                Case TypeMarker.TBoolean

                    fval = IIf((Asc(Mid(data, 2, 1)) > 0), True, False)
                    'if (dbg) then Debug.Print("[.] bool: " & fval)
                    If (dbg) Then Debug.Print("AMFEncode(TypeMarker.TBoolean, " & fval & ") & _")
                    ChompBytes(data, 2)
                    Return True

                Case TypeMarker.TString

                    size = BitConverter.ToUInt16(Encoding.Default.GetBytes(StrReverse(Mid(data, 2, 2))), 0)
                    fval = Mid(data, 4, size)
                    'if (dbg) then Debug.Print("[.] str: " & fval)
                    If (dbg) Then Debug.Print("AMFEncode(TypeMarker.TString, """ & fval & """) & _")
                    ChompBytes(data, (3 + size))
                    Return True

                Case TypeMarker.TObject 'FIXMEFIXMEFIXME
                    'If (dbg) Then Debug.Print("[.] TObject...")
                    'If (dbg) Then Debug.Print(HexDump(fval))
                    data = Mid(data, 2)
                    Dim nest As Integer = 1
                    Dim copy As String = data
                    Dim mk As TypeMarker
                    Dim fv As Object

                    Do While nest > 0
                        fv = Nothing
                        If Left(copy, 3) = Chr(0) & Chr(0) & Chr(9) Then
                            If Len(copy) = 3 Then
                                'Debug.Print("?nest broken @ " & nest)
                                'Return False
                            End If
                            copy = Mid(copy, 4)
                            nest -= 1
                        Else
                            GetField(copy)
                            Select Case Asc(Left(copy, 1))
                                Case 8 : copy = Mid(copy, 6) : nest += 1
                                Case 3 : copy = Mid(copy, 2) : nest += 1
                                Case Else : AMFDecode(copy, mk, fv, False)
                            End Select
                        End If
                    Loop

                    Dim diff As Integer = (Len(data) - Len(copy))
                    fval = Left(data, diff)

                    ChompBytes(data, Len(fval))
                    If (dbg) Then
                        Debug.Print(Space(dent) & "AMFEncode( _")
                        Debug.Print(Space(dent) & "        TypeMarker.TObject, _")
                        DecodeFields(fval, dbg, (dent + 8))
                        Debug.Print(Space(dent) & "    ) & _")
                    End If
                    Return True

                Case TypeMarker.TMovieclip
                    fval = BitConverter.ToUInt32(Encoding.Default.GetBytes(StrReverse(Mid(data, 2, 4))), 0)
                    ChompBytes(data, 5)
                    If (dbg) Then Debug.Print("AMFEncode(TypeMarker.TMovieclip, " & fval & ") & _")
                    'If (dbg) Then Debug.Print("[!] TMovieclip (work needed)...")
                    Return True

                Case TypeMarker.TNull

                    'if (dbg) then Debug.Print("[.] null...")
                    If (dbg) Then Debug.Print("AMFEncode(TypeMarker.TNull, 0) & _")
                    ChompBytes(data, 1)
                    Return True

                Case TypeMarker.TUndefined

                    'if (dbg) then Debug.Print("[.] undef...")
                    If (dbg) Then Debug.Print("AMFEncode(TypeMarker.TUndefined, 0) & _")
                    ChompBytes(data, 1)
                    Return True

                Case TypeMarker.TReference
                    If (dbg) Then Debug.Print("[!] unimplemented decode type: TReference")
                Case TypeMarker.TEcmaarray

                    Dim items As UInt32
                    Dim item As Integer
                    'ChompBytes(data, 8)
                    ChompBytes(data, 1)
                    items = BitConverter.ToUInt32(Encoding.Default.GetBytes(StrReverse(ChompBytes(data, 4))), 0)
                    For item = 1 To items
                        DecodeField(data)
                    Next
                    'Debug.Print(HexDump(Left(data, 16)))
                    ChompBytes(data, 3)

                    'Debug.Print(HexDump(Left(data, 16)))
                    If (dbg) Then Debug.Print("[!] unimplemented decode type: TEcmaarray")
                    Return True

                Case TypeMarker.TObjectend
                    If (dbg) Then Debug.Print("[!] unimplemented decode type: TObjectend")

                Case TypeMarker.TStrictArray
                    If (dbg) Then Debug.Print("[!] unimplemented decode type: TStrictArray")
                Case TypeMarker.TDate
                    If (dbg) Then Debug.Print("[!] unimplemented decode type: TDate")
                Case TypeMarker.TLongString
                    If (dbg) Then Debug.Print("[!] unimplemented decode type: TLongString")
                Case TypeMarker.TUnsupported
                    If (dbg) Then Debug.Print("[!] unimplemented decode type: TUnsupported")
                Case TypeMarker.TRecordset
                    If (dbg) Then Debug.Print("[!] unimplemented decode type: TRecordset")
                Case TypeMarker.TXMLDocument
                    If (dbg) Then Debug.Print("[!] unimplemented decode type: TXMLDocument")
                Case TypeMarker.TTypedObject
                    If (dbg) Then Debug.Print("[!] unimplemented decode type: TTypedObject")
                Case Else : Return False
            End Select
            data = vbNullString
        Catch ex As Exception
            If (dbg) Then Debug.Print("[!] decoder error: " & ex.Message.ToLower)
            If (dbg) Then Debug.Print("[*] dumping data...")
            If (dbg) Then Debug.Print(HexDump(data))
            If (dbg) Then Debug.Print("[*] dumping buffer...")
            If (dbg) Then Debug.Print(HexDump(m_sBuff))
            If (dbg) Then Debug.Print("i can has formats? :(")
        End Try

        Return False

    End Function

    Public Function AMFEncode(ByVal marker As TypeMarker, ByVal fval As Object)

        Dim svar As String = vbNullString

        svar &= Chr(marker)

        Select Case marker
            Case TypeMarker.TNumber

                Dim bytes() As Byte = BitConverter.GetBytes(CLng(fval))
                svar &= Encoding.Default.GetString(bytes)
                'svar &= StrReverse(Encoding.Default.GetString(bytes))

            Case TypeMarker.TBoolean

                svar &= Chr(IIf(fval = True, 1, 0))

            Case TypeMarker.TString

                svar &= Chr(Len(fval) \ 256) & Chr(Len(fval) Mod 256)
                svar &= fval

            Case TypeMarker.TObject

                svar &= fval & Chr(0) & Chr(0) & Chr(9)

            Case TypeMarker.TMovieclip

            Case TypeMarker.TNull
            Case TypeMarker.TUndefined

            Case TypeMarker.TReference
            Case TypeMarker.TEcmaarray
            Case TypeMarker.TObjectend
            Case TypeMarker.TStrictArray
            Case TypeMarker.TDate
            Case TypeMarker.TLongString
            Case TypeMarker.TUnsupported
            Case TypeMarker.TRecordset
            Case TypeMarker.TXMLDocument
            Case TypeMarker.TTypedObject
        End Select

        Return svar

    End Function

    Sub SendConnect()

        Dim body As String

        With Connection
            body = SetField(TypeMarker.TString, "app", .app)
            body &= SetField(TypeMarker.TString, "flashVer", .flashVer)
            body &= SetField(TypeMarker.TString, "swfUrl", .swfUrl)
            body &= SetField(TypeMarker.TString, "tcUrl", .tcUrl)
            body &= SetField(TypeMarker.TBoolean, "fpad", .fpad)
            body &= SetField(TypeMarker.TNumber, "audioCodecs", .audioCodecs)
            body &= SetField(TypeMarker.TNumber, "videoCodecs", .videoCodecs)
            body &= SetField(TypeMarker.TString, "pageUrl", .pageUrl)
        End With
        'body &= SetField(TypeMarker.TNumber, "capabilities", 15)

        body = _
            AMFEncode(TypeMarker.TString, "connect") & _
            AMFEncode(TypeMarker.TNumber, 61503) & _
            Chr(3) & body & Chr(0) & Chr(0) & Chr(9) & _
            m_sConnectData

        Dim copy(1535) As Byte
        Dim int24() As Integer = _
            { _
                (Len(body) \ 65536), _
                ((Len(body) \ 256) Mod 256), _
                (Len(body) Mod 256) _
            }

        Dim rtmp() As Byte = {&H3, 0, 0, 0, int24(0), int24(1), int24(2), RMTPDatatype.Invoke, 0, 0, 0, 0}

        Dim newb As String = vbNullString
        Dim i As Integer = 0

        Do While i < Len(body)
            If (i Mod 128 = 0) And (i <> 0) Then newb &= Chr(&HC3)
            i += 1
            newb &= Mid(body, i, 1)
        Loop

        Dim newbbytes() As Byte = Encoding.Default.GetBytes(newb)

        Debug.Print("[*] sending connect request...")

        Try
            m_sck.Send(copy, copy.Length, SocketFlags.None)
            m_sck.Send(rtmp, rtmp.Length, SocketFlags.None)
            m_sck.Send(newbbytes, newbbytes.Length, SocketFlags.None)
        Catch ex As Exception
            Debug.Print("[!] closeSocket : " & ex.ToString.ToLower)
            CloseSocket()
        End Try

    End Sub

    Sub SendHandshake()

        Dim hshk1() As Byte = {3}
        'Dim hshk2(HANDSHAKE_SIZE - 1) As Byte
        Dim hshk2() As Byte
        Dim hshk3 As String = _
            HexStr( _
                "05 7c f1 6d 00 00 00 00 d2 37 fb 75 b8 e9 19 7c " & _
                "6e ce 47 00 74 ff 05 ff 4a 02 d3 7c 70 00 31 00 " & _
                "66 00 9f 00 ac 00 9d 00 c2 00 ab 00 28 ff 49 ff " & _
                "5e 00 f7 00 e4 fa 35 07 3a 00 83 00 e0 10 61 7c " & _
                "56 01 4f 7c 1c cb cd 00 b2 00 5b 00 98 d7 79 00 " & _
                "4e 01 a7 7c 54 f9 65 07 2a 00 33 00 50 02 91 7c " & _
                "46 00 ff 00 8c 0a fd 00 a2 00 0b 00 08 d8 a9 00 " & _
                "3e f8 57 07 c4 fe 95 07 1a fb e3 07 c0 e9 c1 7c " & _
                "36 02 af 7c fc ff 2d ff 92 02 bb 7c 78 01 d9 7c " & _
                "2e 01 07 7c 34 cb c5 00 0a 00 93 00 30 00 f1 00 " & _
                "26 f9 5f 07 6c 00 5d 00 82 02 6b 7c e8 00 09 00 " & _
                "1e 07 b7 00 a4 00 f5 00 fa 00 43 00 a0 f9 21 07 " & _
                "16 fb 0f 07 dc fb 8d 07 72 e9 1b 7c 58 02 39 7c " & _
                "0e ff 67 ff 14 0f 25 00 ea 10 f3 7c 10 01 51 7c " & _
                "06 00 bf 00 4c 00 bd 00 62 00 cb 00 c8 e9 69 7c " & _
                "fe 02 17 7c 84 ff 55 ff da 02 a3 7c 80 f9 81 07 " & _
                "f6 fc 6f 7c bc 00 ed 00 52 00 7b 00 38 00 99 00 " & _
                "ee 00 c7 00 f4 fa 85 07 ca fd 53 7c f0 00 b1 00 " & _
                "e6 00 1f 00 2c 00 1d 00 42 00 2b 00 a8 fa c9 07 " & _
                "de 00 77 00 64 fd b5 7c ba 00 03 00 60 ff e1 ff " & _
                "d6 00 cf 00 9c 00 4d 00 32 e0 db 7f 18 fa f9 07 " & _
                "ce 10 27 00 d4 00 e5 00 aa 00 b3 00 d0 00 11 00 " & _
                "c6 00 7f 00 0c 00 7d 00 22 fa 8b 00 88 f9 29 07 " & _
                "be da d7 7c 44 2d 15 7c 9a 00 63 00 40 fd 41 07 " & _
                "b6 fd 2f 07 7c 00 ad 00 12 ff 3b ff f8 00 59 00 " & _
                "ae fe 87 07 b4 06 45 7c 8a db 13 7c b0 06 71 7c " & _
                "a6 03 df 00 ec 06 dd 7c 02 00 eb 00 68 a1 89 06 " & _
                "9e 2e 37 06 24 00 75 00 7a 46 c3 24 20 00 a1 00 " & _
                "96 a2 8f 77 5c 35 0d 01 f2 01 9b 01 d8 01 b9 00 " & _
                "8e c0 e7 7f 94 0c a5 00 6a 04 73 00 90 00 d1 00 " & _
                "86 00 3f 00 cc 00 3d 00 e2 fa 4b 07 48 fa e9 07 " & _
                "7e 00 97 00 04 00 d5 00 5a 00 23 00 00 00 01 07 " & _
                "76 f0 ef 07 3c 00 6d 07 d2 a1 fb 06 b8 a1 19 06 " & _
                "6e 0c 47 00 74 04 05 00 4a ff d3 ff 70 00 31 00 " & _
                "66 00 9f 00 ac 03 9d 00 c2 00 ab 00 28 00 49 00 " & _
                "5e ff f7 ff e4 02 35 7c 3a 01 83 7c e0 01 61 7c " & _
                "56 00 4f 00 1c fd cd 07 b2 00 5b 00 98 00 79 00 " & _
                "4e 00 a7 7c 54 cd 65 00 2a fa 33 07 50 00 91 00 " & _
                "46 00 ff 7c 8c d8 fd 00 a2 fb 0b 07 08 00 a9 00 " & _
                "3e 00 57 7c c4 cb 95 00 1a fb e3 07 c0 00 c1 7c " & _
                "36 08 af 00 fc 00 2d 7c 92 00 bb 00 78 cb d9 00 " & _
                "2e 01 07 00 34 00 c5 00 0a ce 93 00 30 fc f1 07 " & _
                "26 00 5f 00 6c d7 5d 00 82 ff 6b 00 e8 16 09 71 " & _
                "1e fc b7 07 a4 2c f5 01 fa 00 43 00 a0 00 21 00 " & _
                "16 00 0f 00 dc 00 8d 00 72 21 1b 71 58 d2 39 7c " & _
                "0e a1 67 06 14 02 25 00 ea 04 f3 00 10 6e 51 30 " & _
                "06 00 bf 00 4c 06 bd 7c 62 00 cb 00 c8 30 69 00 " & _
                "fe ff 17 07 84 00 55 00 da 00 a3 00 80 00 81 00 " & _
                "f6 2b 6f 01 bc 4d ed 71 52 fc 7b 07 38 00 99 00 " & _
                "ee 00 c7 00 f4 00 85 00 ca a9 53 03 f0 00 b1 00 " & _
                "e6 fb 1f 07 2c 00 1d 00 42 00 2b 00 a8 00 c9 00 " & _
                "de 00 77 00 64 00 b5 00 ba 00 03 00 60 00 e1 00 " & _
                "d6 00 cf 00 9c 00 4d 00 32 20 db 00 18 20 f9 00 " & _
                "ce 00 27 00 d4 00 e5 00 aa 03 b3 00 d0 00 11 00 " & _
                "c6 00 7f 00 0c 00 7d 00 22 00 8b 00 88 00 29 00 " & _
                "be 00 d7 00 44 00 15 00 9a 00 63 00 40 00 41 00 " & _
                "b6 fc 2f 07 7c 00 ad 00 12 00 3b 7c f8 20 59 03 " & _
                "ae fc 87 07 b4 00 45 7c 8a 07 13 00 b0 00 71 7c " & _
                "a6 16 df 71 ec fd dd 07 02 2c eb 01 68 2b 89 01 " & _
                "9e fc 37 07 24 2b 75 01 7a fd c3 07 20 21 a1 71 " & _
                "96 d2 8f 7c 5c 4d 0d 71 f2 02 9b 00 d8 04 b9 00 " & _
                "8e 00 e7 00 94 00 a5 00 6a fc 73 07 90 20 d1 00 " & _
                "86 fc 3f 07 cc 00 3d 00 e2 00 4b 00 48 00 e9 00 " & _
                "7e 00 97 00 04 2b d5 01 5a 4d 23 71 00 fd 01 07 " & _
                "76 00 ef 00 3c 00 6d 00 d2 00 fb 00 b8 a9 19 03 " & _
                "6e 00 47 00 74 fc 05 07 4a 00 d3 00 70 00 31 7c " & _
                "66 ee 9f 03 ac fd 9d 07 c2 00 ab 7c 28 07 49 00 " & _
                "5e 00 f7 7c e4 ee 35 03 3a ee 83 03 e0 35 61 01 " & _
                "56 20 4f 00 1c 00 cd 00 b2 00 5b 00 98 03 79 00 " & _
                "4e 00 a7 00 54 00 65 00 2a 00 33 00 50 00 91 00 " & _
                "46 fd ff 07 8c 00 fd 00 a2 00 0b 7c 08 99 a9 00 " & _
                "3e fd 57 07 c4 00 95 7c 1a 09 e3 00 c0 00 c1 7c " & _
                "36 99 af 00 fc 34 2d 01 92 35 bb 01 78 fd d9 07 " & _
                "2e 00 07 00 34 00 c5 7c 0a 34 93 01 30 fd f1 07 " & _
                "26 00 5f 7c 6c 0b 5d 01 82 00 6b 7c e8 34 09 01 " & _
                "1e 00 b7 00 a4 00 f5 00 fa 00 43 00 a0 00 21 00 " & _
                "16 00 0f 00 dc 00 8d 00 72 00 1b 00 58 00 39 00 " & _
                "0e 00 67 00 14 00 25 00 ea fc f3 07 10 00 51 00 " & _
                "06 fd bf 07 4c e9 bd 7c 62 00 cb 7c c8 ff 69 ff " & _
                "fe 00 17 7c 84 14 55 7c da 00 a3 00 80 00 81 00 " & _
                "f6 0c 6f 00 bc 0c ed 00 52 67 7b 00 38 00 99 00 " & _
                "ee 00 c7 00 f4 00 85 00 ca 00 53 00 f0 fd b1 07 " & _
                "e6 03 1f 00 2c 0c 1d 00 42 04 2b 00 a8 14 c9 7c " & _
                "de 00 77 01 64 13 b5 7c ba 34 03 01 60 00 e1 00 " & _
                "d6 00 cf 00 9c 02 4d 03 32 cd db 00 18 00 f9 00 " & _
                "ce fd 27 07 d4 00 e5 00 aa fe b3 07 d0 e9 11 7c " & _
                "c6 00 7f 7c 0c ff 7d ff 22 00 8b 7c 88 42 29 71 " & _
                "be 00 d7 01 44 00 15 00 9a 34 63 01 40 00 41 00 " & _
                "b6 34 2f 01 7c 34 ad 01 12 34 3b 00 f8 fe 59 07 " & _
                "ae 41 87 71 b4 41 45 71 8a 01 13 00 b0 dd 71 00 " & _
                "a6 ff df 07 ec 00 dd 00 02 ff eb 07 68 24 89 71 " & _
                "9e 45 37 71 24 ff 75 ff 7a 52 c3 00 20 fa a1 07 " & _
                "96 00 8f 00 5c ff 0d 07 f2 9a 9b 7c d8 06 b9 7c " & _
                "8e ff e7 ff 94 06 a5 7c 6a 06 73 7c 90 ff d1 ff " & _
                "86 00 3f 00 cc 00 3d 00 e2 6e 4b 30 48 a1 e9 06 " & _
                "7e 00 97 00 04 a1 d5 06 5a fe 23 07 00 6e 01 30" _
            )

        hshk2 = Encoding.Default.GetBytes(hshk3)

        Debug.Print("[*] sending rtmp handshake...")
        m_sck.Send(hshk1, 1, SocketFlags.None)
        m_sck.Send(hshk2, HANDSHAKE_SIZE, SocketFlags.None)

    End Sub

    Sub SendPacket(ByVal sobject As Byte, ByVal dt As RMTPDatatype, ByVal data As String)

        Dim int24() As Integer = _
            { _
                (Len(data) \ 65536), _
                ((Len(data) \ 256) Mod 256), _
                (Len(data) Mod 256) _
            }
        Dim objectid As Byte = (&H1F And sobject)
        Dim rtmp() As Byte = {objectid, 0, 0, 0, int24(0), int24(1), int24(2), dt, 0, 0, 0, 0}
        Dim payload As String = vbNullString
        Dim i As Integer = 0

        Do While i < Len(data)
            If (i Mod 128 = 0) And (i <> 0) Then payload &= Chr(objectid + &HC0)
            i += 1
            payload &= Mid(data, i, 1)
        Loop
        Dim newbbytes() As Byte = Encoding.Default.GetBytes(payload)

        'Debug.Print("[*] sending packet...")

        Try
            If m_sck.Connected Then
                m_sck.Send(rtmp, rtmp.Length, SocketFlags.None)
                m_sck.Send(newbbytes, newbbytes.Length, SocketFlags.None)
            Else
                Debug.Print("[!] unable to send packet, socket not connected")
            End If
        Catch ex As Exception
            Debug.Print("[!] sendpacket : " & ex.ToString.ToLower)
            CloseSocket()
        End Try

    End Sub

    Protected Overrides Sub Finalize()
        MyBase.Finalize()
    End Sub

    Public Class clsRTMPObject

        Public m_nTimeStamp As Integer = 0
        Public m_nPacketSize As Integer = 0
        Public m_nStreamId As Integer = 0
        Public m_bRTMPDataType As RMTPDatatype

    End Class

    Public Class clsAMFValue

        Public varType As RMTPDatatype
        Public varValue As Object

    End Class

    Public Class clsConnectionSettings

        '"WIN 10,0,12,36"
        '"WIN 9,0,47,0"

        Private m_sApp As String = "flashcoms_5_1_videochat"
        Private m_sFlashVer As String = "WIN 8,0,24,0"
        Private m_sSwfUrl As String = "http://www.rudester.com/flashcoms/video.chat/videochat.swf?anticash=526"
        Private m_sTcUrl As String = "rtmp://rudester.com/flashcoms_5_1_videochat"
        Private m_bFPad As Boolean = False
        Private m_dAudioCodecs As UInt64 = 1639
        Private m_dVideoCodecs As UInt64 = 252
        Private m_sPageUrl As String = "http://www.rudester.com/video_chat.php"

        Public Property app() As String
            Get
                app = m_sApp
            End Get
            Set(ByVal application As String)
                m_sApp = application
            End Set
        End Property

        Public Property flashVer() As String
            Get
                flashVer = m_sFlashVer
            End Get
            Set(ByVal flashVersion As String)
                m_sFlashVer = flashVersion
            End Set
        End Property

        Public Property swfUrl() As String
            Get
                swfUrl = m_sSwfUrl
            End Get
            Set(ByVal url As String)
                m_sSwfUrl = url
            End Set
        End Property

        Public Property tcUrl() As String
            Get
                tcUrl = m_sTcUrl
            End Get
            Set(ByVal url As String)
                m_sTcUrl = url
            End Set
        End Property

        Public Property fpad() As Boolean
            Get
                fpad = m_bFPad
            End Get
            Set(ByVal pad As Boolean)
                m_bFPad = pad
            End Set
        End Property

        Public Property audioCodecs() As UInt64
            Get
                audioCodecs = m_dAudioCodecs
            End Get
            Set(ByVal codecs As UInt64)
                m_dAudioCodecs = codecs
            End Set
        End Property

        Public Property videoCodecs() As UInt64
            Get
                videoCodecs = m_dVideoCodecs
            End Get
            Set(ByVal codecs As UInt64)
                m_dVideoCodecs = codecs
            End Set
        End Property

        Public Property pageUrl() As String
            Get
                pageUrl = m_sPageUrl
            End Get
            Set(ByVal url As String)
                m_sPageUrl = url
            End Set
        End Property

    End Class

End Class


