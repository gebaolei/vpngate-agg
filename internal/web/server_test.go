package web

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
)

// 启动日志里的「本机地址」是给人直接点开的，拼错一个字符就是废字符串。
//
// 之前 listen=":8080" 时 Addr() 是 "[::]:8080"，按第一个冒号切字符串切出来
// 是 "http://127.0.0.1::]:8080"，看着像地址、其实点不开。
func TestLocalAddrsAreClickable(t *testing.T) {
	for _, network := range []string{"tcp", "tcp4"} {
		ln, err := net.Listen(network, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		got := localAddrs(ln)
		want := fmt.Sprintf("http://127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port)
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s 绑到 127.0.0.1 时应只报 %q，实得 %v", network, want, got)
		}
		ln.Close()
	}

	// 监听所有网卡时才列出多个，而且每一个都得是能解析、能点开的 URL。
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	got := localAddrs(ln)
	if len(got) < 1 {
		t.Fatal("一个地址都没列出来")
	}
	found := false
	for _, u := range got {
		if strings.Contains(u, "]") {
			t.Errorf("%q 里还带着 Addr() 的方括号", u)
		}
		parsed, err := url.Parse(u)
		if err != nil {
			t.Errorf("%q 解析失败: %v", u, err)
			continue
		}
		if parsed.Scheme != "http" || parsed.Hostname() == "" || parsed.Port() == "" {
			t.Errorf("%q 不像能点开的地址", u)
		}
		if parsed.Port() != fmt.Sprint(port) {
			t.Errorf("%q 的端口不是实际监听的 %d", u, port)
		}
		if parsed.Hostname() == "127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("%v 里没有 127.0.0.1，用户在本机就没法直接打开", got)
	}
}
