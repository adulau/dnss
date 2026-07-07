package dnstap

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestWriteControlFrameStreamsFormat(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() {
		done <- writeControl(client, fstrmControlReady, contentType)
	}()

	buf := make([]byte, 8+4+8+len(contentType))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatalf("failed to read control frame: %v", err)
	}

	expected := []byte{
		0, 0, 0, 0, // Control frame escape.
		0, 0, 0, byte(4 + 8 + len(contentType)), // Control frame length.
		0, 0, 0, fstrmControlReady, // Control frame type.
		0, 0, 0, fstrmControlFieldContentType, // Field type.
		0, 0, 0, byte(len(contentType)), // Field length.
	}
	expected = append(expected, contentType...)
	if !bytes.Equal(buf, expected) {
		t.Fatalf("control frame mismatch:\n got %v\nwant %v", buf, expected)
	}

	server.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("writeControl returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("writeControl did not return")
	}
}
