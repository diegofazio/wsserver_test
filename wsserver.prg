#include "inkey.ch"
#include "hbsocket.ch"

#define ADDRESS    "0.0.0.0"
#define PORT       9000
#define TIMEOUT    3000    // 3 seconds
#define CRLF       Chr( 13 ) + Chr( 10 )
#define FILEHEADER "data:application/octet-stream;base64,"
#define JSONHEADER "data:application/json;base64,"
#define HTMLHEADER "data:text/html;base64,"

#define OPC_CONT   0x00
#define OPC_TEXT   0x01
#define OPC_BIN    0x02
#define OPC_CLOSE  0x08
#define OPC_PING   0x09
#define OPC_PONG   0x0A

REQUEST DBFCDX

// ----------------------------------------------------------------//

FUNCTION Main()

   LOCAL hListen, hSocket

   hb_FileDelete( "./data/users.dbf" )
   hb_FileDelete( "./data/users.cdx" )

   dbCreate( "./data/users", ;
      { { "USER",      "C", 10, 0 }, ;
      { "CLOGIN",    "C",  1, 0 }, ;
      { "CACTIVE",   "C",  1, 0 } } )

   dbUseArea( .F., "DBFCDX", "./data/users",, .T. )
   dbCreateIndex( "./data/users.cdx", "USER" )

   IF ! hb_mtvm()
      ? "multithread support required"
      RETURN
   ENDIF

   IF Empty( hListen := hb_socketOpen( HB_SOCKET_AF_INET, HB_SOCKET_PT_STREAM, HB_SOCKET_IPPROTO_TCP ) )
      ? "socket create error " + hb_ntos( hb_socketGetError() )
   ENDIF

   IF ! hb_socketBind( hListen, { HB_SOCKET_AF_INET, ADDRESS, PORT } )
      ? "bind error " + hb_ntos( hb_socketGetError() )
   ENDIF

   IF ! hb_socketListen( hListen )
      ? "listen error " + hb_ntos( hb_socketGetError() )
   ENDIF

   ? "Harbour websockets server running on port " + hb_ntos( PORT )

   WHILE .T.
      IF Empty( hSocket := hb_socketAccept( hListen,, TIMEOUT ) )
         IF hb_socketGetError() == HB_SOCKET_ERR_TIMEOUT
            // ? "loop"
         ELSE
            ? "accept error " + hb_ntos( hb_socketGetError() )
         ENDIF
      ELSE
         ? "accept socket request"
         hb_threadStart( @ServeClient(), hSocket )
      ENDIF
      IF Inkey() == K_ESC
         ? "quitting - esc pressed"
         EXIT
      ENDIF
   END

   ? "close listening socket"

   hb_socketShutdown( hListen )
   hb_socketClose( hListen )

RETURN NIL

// ----------------------------------------------------------------//

FUNCTION HandShaking( hSocket, cHeaders )

   LOCAL aHeaders := hb_ATokens( cHeaders, CRLF )
   LOCAL hHeaders := { => }, cLine
   LOCAL cAnswer

   FOR EACH cLine in aHeaders
      hHeaders[ SubStr( cLine, 1, At( ":", cLine ) - 1 ) ] = SubStr( cLine, At( ":", cLine ) + 2 )
   NEXT

   cAnswer = "HTTP/1.1 101 Web Socket Protocol Handshake" + CRLF + ;
      "Upgrade: websocket" + CRLF + ;
      "Connection: Upgrade" + CRLF + ;
      "WebSocket-Origin: " + ADDRESS + CRLF + ;
      "WebSocket-Location: ws://" + ADDRESS + ":" + hb_ntos( PORT ) + CRLF + ;
      "Sec-WebSocket-Accept: " + ;
      hb_base64Encode( hb_SHA1( hHeaders[ "Sec-WebSocket-Key" ] + ;
      "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", .T. ) ) + CRLF + CRLF

   hb_socketSend( hSocket, cAnswer )

RETURN NIL

// ----------------------------------------------------------------//

FUNCTION Unmask( cBytes, nOpcode )

   LOCAL lComplete := hb_bitTest( hb_BPeek( cBytes, 1 ), 7 )
   LOCAL nFrameLen := hb_bitAnd( hb_BPeek( cBytes, 2 ), 127 )
   LOCAL nLength, cMask, cData, cChar, cHeader := ""

   nOpcode := hb_bitAnd( hb_BPeek( cBytes, 1 ), 15 )

   DO CASE
   CASE nFrameLen <= 125
      nLength = nFrameLen
      cMask = SubStr( cBytes, 3, 4 )
      cData = SubStr( cBytes, 7 )

   CASE nFrameLen = 126
      nLength = ( hb_BPeek( cBytes, 3 ) * 256 ) + hb_BPeek( cBytes, 4 )
      cMask   = SubStr( cBytes, 5, 4 )
      cData   = SubStr( cBytes, 9 )

   CASE nFrameLen = 127
      nLength = NetworkBin2ULL( SubStr( cBytes, 3, 8 ) )
      cMask   = SubStr( cBytes, 11, 4 )
      cData   = SubStr( cBytes, 15 )
   ENDCASE

   cBytes = ""
   FOR EACH cChar in cData
      cBytes += Chr( hb_bitXor( Asc( cChar ), ;
         hb_BPeek( cMask, ( ( cChar:__enumIndex() - 1 ) % 4 ) + 1 ) ) )
   NEXT

   DO CASE
   CASE Left( cBytes, Len( FILEHEADER ) ) == FILEHEADER
      cBytes = hb_base64Decode( SubStr( cBytes, Len( FILEHEADER ) + 1 ) )
      cHeader = FILEHEADER

   CASE Left( cBytes, Len( JSONHEADER ) ) == JSONHEADER
      cBytes = hb_base64Decode( SubStr( cBytes, Len( JSONHEADER ) + 1 ) )
      cHeader = JSONHEADER

   CASE Left( cBytes, Len( HTMLHEADER ) ) == HTMLHEADER
      cBytes = hb_base64Decode( SubStr( cBytes, Len( HTMLHEADER ) + 1 ) )
      cheader = HTMLHEADER
   ENDCASE

RETURN cBytes

// ----------------------------------------------------------------//

FUNCTION NetworkULL2Bin( n )

   LOCAL nBytesLeft := 64
   LOCAL cBytes := ""

   WHILE nBytesLeft > 0
      nBytesLeft -= 8
      cBytes += Chr( hb_bitAnd( hb_bitShift( n, - nBytesLeft ), 0xFF ) )
   END

RETURN cBytes

// ----------------------------------------------------------------//

FUNCTION NetworkBin2ULL( cBytes )

   LOCAL cByte, n := 0

   FOR EACH cByte in cBytes
      n += hb_bitShift( Asc( cByte ), 64 - cByte:__enumIndex() * 8 )
   NEXT

RETURN n

// ----------------------------------------------------------------//

FUNCTION Mask( cText, nOPCode )

   LOCAL nLen := Len( cText )
   LOCAL cHeader
   LOCAL lMsgIsComplete := .T.
   LOCAL nFirstByte := 0

   hb_default( @nOPCode, OPC_TEXT )

   IF lMsgIsComplete
      nFirstByte = hb_bitSet( nFirstByte, 7 ) // 1000 0000
   ENDIF

   // setting OP code
   nFirstByte := hb_bitOr( nFirstByte, nOPCode )  // 1000 XXXX -> is set

   DO CASE
   CASE nLen <= 125
      cHeader = Chr( nFirstByte ) + Chr( nLen )

   CASE nLen < 65536
      cHeader = Chr( nFirstByte ) + Chr( 126 ) + ;
         Chr( hb_bitShift( nLen, - 8 ) ) + Chr( hb_bitAnd( nLen, 0xFF ) )

   OTHERWISE
      cHeader = Chr( nFirstByte ) + Chr( 127 ) + NetworkULL2Bin( nLen )
   ENDCASE

RETURN cHeader + cText

// ----------------------------------------------------------------//

FUNCTION ServeClient( hSocket )

   LOCAL cRequest, cBuffer := Space( 4096 ), nLen, nOpcode
   LOCAL hResp := { => }, hReq := { => }
   LOCAL cUser := ''
   LOCAL nUserTyping := 0
   LOCAL nMillis := hb_MilliSeconds()

   hb_socketRecv( hSocket, @cBuffer,,, 1024 )
   HandShaking( hSocket, RTrim( cBuffer ) )

   ? "new client connected"

   dbUseArea( .F., "DBFCDX", "./data/users", "users", .T. )

   users->( dbSetOrder( 1 ) )

   ErrorBlock( {| oError | CloseClient( cUser, hSocket ) } )

   WHILE .T.
      cRequest = ""
      nLen = 1

      WHILE nLen > 0
         cBuffer := Space( 4096 )
         IF ( nLen := hb_socketRecv( hSocket, @cBuffer,,, TIMEOUT ) ) > 0
            cRequest += Left( cBuffer, nLen )
         ELSE
            IF nLen == -1 .AND. hb_socketGetError() == HB_SOCKET_ERR_TIMEOUT
               nLen = 0
            ENDIF
         ENDIF
      END

      IF ! Empty( cRequest )

         cRequest := UnMask( cRequest, @nOpcode )
         hb_jsonDecode( cRequest, @hReq )

         IF Empty( cUser )

            cUser := AllTrim( hReq[ 'user' ] )

         ENDIF

         IF hReq[ 'type' ] == 'exit'

            CloseClient( cUser, hSocket )

         ENDIF

         IF hReq[ 'type' ] == 'typingstate'

            nUserTyping := hReq[ 'value' ]

            DO WHILE !users->( RLock() )
            ENDDO

            IF nUserTyping == 1

               users->cActive := "1"
            ELSE

               users->cActive := "0"

            ENDIF

         ENDIF

      ENDIF

      IF (  hb_MilliSeconds() > ( nMillis + 1000 ) ) .AND. Len( cUser ) != 0
         nMillis = hb_MilliSeconds()
         users->( dbSeek( cUser, .F. ) )

         IF !Found()

            APPEND BLANK
            users->user = cUser

         ENDIF

         DO WHILE !users->( RLock() )
         ENDDO

         users->cLogin := "1"

         IF nUserTyping == 1

            users->cActive := "1"
         ELSE

            users->cActive := "0"

         ENDIF

         // get users online and users typing
         users->( dbGoTop() )
         cHtml := 'Usuarios conectados:<br>'
         nTyping := 0
         cTyping := ''
         nOnline := 0

         DO WHILE !users->( Eof() )

            IF ( users->cLogin == "1" )
               nOnline++
               cHtml += '<li>' + hb_eol()
               cHtml += AllTrim( Upper( users->user ) ) + '<br>'
               cHtml += '</li>' + hb_eol()

               IF users->cActive == "1" .AND. users->user != cUser
                  nTyping++

                  IF nTyping > 3
                     cTyping := 'Varios usuarios escribiendo...'
                  ELSE
                     cTyping += iif( nTyping != 1, ', ', '' ) + users->user
                  ENDIF

               ENDIF
            ENDIF

            users->( dbSkip() )

         ENDDO

         hResp[ 'users' ] = cHtml
         hResp[ 'typing' ] = iif( nTyping != 0, iif( nTyping != 3, iif( nTyping == 1, cTyping + " esta ", cTyping + " estan " ) + " escribiendo...", cTyping ), '' )
         hResp[ 'type' ] = 'updusersdata'
         hb_socketSend( hSocket, Mask( hb_jsonEncode( hResp, .T. ) ) )

      ENDIF
   ENDDO

RETURN NIL


FUNCTION CloseClient( cUser, hSocket )

   IF Len( cUser ) != 0

      users->( dbSeek( cUser, .F. ) )

      IF Found()

         DO WHILE !users->( RLock() )
         ENDDO

         users->cLogin := "0"
         users->cActive := "0"

      ENDIF

   ENDIF
   ? "User ", cUser, " disconnected"

   hb_socketShutdown( hSocket )
   hb_socketClose( hSocket )

   QUIT

RETURN
// ----------------------------------------------------------------//
