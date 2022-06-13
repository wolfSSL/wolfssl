package main

import (
    "net"
    "os"
    "fmt"
)

/* Connection configuration constants */
const (
    CONN_HOST = "localhost"
    CONN_PORT = "11111"
    CONN_TYPE = "tcp"
)

func main() {
    /* Client Certificate path */
    CERT_FILE := "../../../certs/ca-cert.pem"

    /* Initialize wolfSSL */
    wolfSSL_Init()

    /* Create WOLFSSL_CTX with tlsv12 */
    ctx := wolfSSL_CTX_new(wolfTLSv1_2_client_method())
    if ctx == nil {
        fmt.Println(" CTX new Failed");
        os.Exit(1)
    }

    /* Load client certificate into WOLFSSL_CTX */
    ret := wolfSSL_CTX_load_verify_locations(ctx, CERT_FILE, nil)
    if ret != WOLFSSL_SUCCESS {
        fmt.Println("Failed to load ", CERT_FILE);
        os.Exit(1)
    }

    /* Create a WOLFSSL object */
    ssl := wolfSSL_new(ctx)
    if ssl == nil {
        fmt.Println(" wolfSSL_new failed");
        os.Exit(1)
    }

    /* Get address of TCP end point */
    tcpAddr, err := net.ResolveTCPAddr(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
    if err != nil {
        println("ResolveTCPAddr failed:", err.Error())
        os.Exit(1)
    }

    /* Dial the recieved TCP address */
    conn, err := net.DialTCP(CONN_TYPE, nil, tcpAddr)
    if err != nil {
        println("Dial failed:", err.Error())
        os.Exit(1)
    }

    /* Retrieve file descriptor from net.*TCPConn type */
    file,err := conn.File()
    fd := file.Fd()
    wolfSSL_set_fd(ssl, int(fd))

    /* Connect to wolfSSL on the server side */
    ret = wolfSSL_connect(ssl);
    if ret != WOLFSSL_SUCCESS {
        fmt.Println(" wolfSSL_connect error ", ret);
        os.Exit(1)
    } else {
        fmt.Println("Succesfully Connected!");
    }

    /* Create the message and send to server */
    message := []byte("Can you hear me?")
    sz := uintptr(len(message))

    ret = wolfSSL_write(ssl, message, sz)
    if uintptr(ret) != sz {
        fmt.Println(" wolfSSL_write failed ");
        os.Exit(1)
    }


    /* Recieve then print the message from server */
    buf := make([]byte, 256)
    ret = wolfSSL_read(ssl, buf, 256)
    if ret == -1 {
        fmt.Println(" wolfSSL_read failed ");
    } else {
        fmt.Println("Server says : ", string(buf));
    }

    /* Shutdown wolfSSL */
    wolfSSL_shutdown(ssl)
    /* Free wolfSSL and wolfSSL_CTX objects */
    wolfSSL_free(ssl)
    wolfSSL_CTX_free(ctx)
    /* Cleanup the wolfSSL environment */
    wolfSSL_Cleanup()

    /* Close the connection */
    conn.Close()
}
