---
layout: post
title: "Firewall を貫くツールを自作してみた"
date: 2015-12-23 12:42:51 +0900
comments: true
categories: 
keywords: firewall,ファイアウォール,socks,socks5
---

これは [【その2】ドリコム Advent Calendar 2015](http://www.adventar.org/calendars/1044) 24日目の記事です。  
22日目の記事は hayato240 さんの[二郎を思い浮かべながら、RSpecを学んだことの振り返り](http://qiita.com/hayato240/items/d20e27da7d24a3bd3af2) です。  
[【その1】ドリコム Advent Calendar 2015](http://www.adventar.org/calendars/1043) もあわせてどうぞ。

## 自己紹介

こんにちは、タイガーです。

中国上海からきてます。ドリコム歴はもう４年目です。  
本業はサーバーサイドのエンジニアです。今年は iOS と Android のクライアントの開発も結構やりました。

## まえがき

この間 [Great Firewall](http://www.wikiwand.com/ja/%E9%87%91%E7%9B%BE) が VPN も遮断するニュースがありまして、ちょっと周りの人とその話をしました。

多分エンジニアの皆さんはご存知と思います。中国にいるならこれを越えないといろいろ不便になります。そのためにいろんなツールも作られています。一番有名のは [shadowsocks](https://github.com/shadowsocks/shadowsocks)、見ての通りいつかその存在が消えるかもしれませんね。エンジニアとしてはやはり自分がその仕組を理解すれば一番いいと思います。

## 本題

Firewall を通過するには、[SOCKS5](https://www.wikiwand.com/en/SOCKS) っていうプロトコルが存在します。具体的な仕様は [RFC1928](https://www.ietf.org/rfc/rfc1928.txt) に定義されています。８ページしかないので、割りとすぐ読み終えます。基本的は SOCKS5 をベースにして作ればいろいろ汎用出来ます。

すでに shadowsocks 大先輩があるので、それを参考にしながら作ってみましょう。言語はもちろん Ruby です。

<!-- more -->

大体な構造は下図の通り

{% img /images/socks-tunnel.png %}

* まずはローカルサーバーとリモートサーバー２つの部分があります。
* ブラウザとかの SOCKS5 をサポートしてるアプリケーションはローカルサーバーに接続します。
* リモートサーバーは Firewall の外にあるサーバーで実行します。
* Firewall の外にアクセスする時は **ブラウザ → ローカルサーバー → リモートサーバー → 目標サーバー** の流れになります。

### ローカルサーバー

まず必要なのは並列処理です。ブラウザは同時にたくさんのアクセスがくるので、並列処理ができないと使い物にならないです。今の時代はもちろん Event Driven I/O でやります。Ruby なら [EventMachine](https://github.com/eventmachine/eventmachine) があります。

とりあえず EventMachine で実装してみました。ちょっと長いです。(´・ω・｀)

```ruby local.rb https://github.com/cctiger36/socks-tunnel-demo/blob/master/local.rb
require "eventmachine"

LOCAL_SERVER_HOST = "127.0.0.1"
LOCAL_SERVER_PORT = "8081"
REMOTE_SERVER_HOST = "127.0.0.1"
REMOTE_SERVER_PORT = "8082"

class LocalConnection < EventMachine::Connection
  attr_accessor :server

  def send_encoded_data(data)
    return if data.nil? || data.length == 0
    send_data(data)
  end

  def receive_data(data)
    server.send_data(data)
  end

  def unbind
    server.close_connection_after_writing
  end
end

module LocalServer

  def post_init
    @fiber = Fiber.new do
      greeting
      loop { do_command }
    end
  end

  def receive_data(data)
    if @connection
      @connection.send_encoded_data(data.to_s)
    else
      @data = data
      @fiber = nil if @fiber.resume
    end
  end

  def unbind
    @connection.close_connection if @connection
  end

  private

    # IN
    # +----+----------+----------+
    # |VER | NMETHODS | METHODS  |
    # +----+----------+----------+
    # | 1  |    1     | 1 to 255 |
    # +----+----------+----------+
    #
    # OUT
    # +----+--------+
    # |VER | METHOD |
    # +----+--------+
    # | 1  |   1    |
    # +----+--------+
    def greeting
      ver = @data.unpack("C")
      clear_data
      if ver == 5
        send_data "\x05\x00"  # NO AUTHENTICATION REQUIRED
      else
        send_data "\x05\xFF"  # NO ACCEPTABLE METHODS
      end
      Fiber.yield
    end

    # IN
    # +----+-----+-------+------+----------+----------+
    # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    # +----+-----+-------+------+----------+----------+
    # | 1  |  1  | X'00' |  1   | Variable |    2     |
    # +----+-----+-------+------+----------+----------+
    #
    # OUT
    # see the defination of reply_data
    def do_command
      _, cmd, _, atype, addr_length = @data.unpack("C5")
      header_length = 0

      case atype
      when 1, 4  # 1: ipv4, 4 bytes / 4: ipv6, 16 bytes
        ip_length = 4 * atype
        host = IPAddr.ntop @data[4, ip_length]
        port = @data[4 + ip_length, 2].unpack('S>').first
        header_length = ip_length + 6
      when 3     # domain name
        host = @data[5, addr_length]
        port = @data[5 + addr_length, 2].unpack('S>').first
        header_length = addr_length + 7
      else
        panic :address_type_not_supported
      end

      case cmd
      when 1
        send_data reply_data(:success)
        @connection = EventMachine.connect(REMOTE_SERVER_HOST, REMOTE_SERVER_PORT, LocalConnection)
        @connection.server = self
        @connection.send_encoded_data("#{host}:#{port}\n")
        @connection.send_encoded_data(@data[header_length, -1])
        clear_data
        Fiber.yield
      when 2, 3  # bind, udp
        panic :command_not_supported
      else
        panic :command_not_supported
      end
    end

    # +----+-----+-------+------+----------+----------+
    # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    # +----+-----+-------+------+----------+----------+
    # | 1  |  1  | X'00' |  1   | Variable |    2     |
    # +----+-----+-------+------+----------+----------+
    def reply_data(type)
      @replies_hash ||= begin
        {
          success:                    0,
          command_not_supported:      7,
          address_type_not_supported: 8,
        }.map { |k, v| [k, ("\x05#{[v].pack('C')}\x00\x01\x00\x00\x00\x00\x00\x00")] }.to_h
      end
      @replies_hash[type]
    end

    def clear_data
      @data = nil
    end

    def panic(reply_type)
      send_data reply_data(reply_type)
      Fiber.yield true
    end
end

EventMachine.run do
  puts "Start socks5 at #{LOCAL_SERVER_HOST}:#{LOCAL_SERVER_PORT}"
  EventMachine.start_server(LOCAL_SERVER_HOST, LOCAL_SERVER_PORT, LocalServer)
end
```

* SOCKS5 の handshake をやるとき連続でデータのやり取りをするから、ここでは [Fiber](http://ruby-doc.org/core-2.2.3/Fiber.html) を使えば効率よくかつかっこ良く実装できます。
* アクセスがきたら、SOCKS のバージョンは５だったら `\x05\x00` を返します。（認識いらないから、NMETHODS と METHODS は無視）
* 次にコマンドのデータがきます。仕様通りホストとポートを解析します。
    * 急いで書いたので、TCP しか実装していません。(´Д｀)
* 解析したホストとポートと転送したいデータをリモートサーバーに送ります。
    * shadowsocks はローカルからリモートへ転送する時も SOCKS5 に従って実装してます。多分リモートサーバーの間に互換性をもたらすためです。こちらはシンプルのため、下記の形でデータを送ります。
    * `<HOST>:<PORT>\nDATA...`

### リモートサーバー

ローカルサーバーに比べたらすごくシンプルなものです。  
上記のホストとポートを取り出し、目標サーバーに接続し、データの部分をそのまま送ります。  
最後は帰ってきたレスポンスを逆の経路でブラウザに返します。

```ruby remote.rb https://github.com/cctiger36/socks-tunnel-demo/blob/master/remote.rb
require "eventmachine"

REMOTE_SERVER_PORT = "8082"

class RemoteConnection < EventMachine::Connection
  attr_accessor :server

  def receive_data(data)
    @server.send_encoded_data(data)
  end

  def unbind
    @server.close_connection_after_writing
  end
end

class RemoteServer < EventMachine::Connection
  def post_init
    @buffer = ""
  end

  def send_encoded_data(data)
    return if data.nil? || data.length == 0
    # TODO: encode data
    send_data(data)
  end

  def receive_data(data)
    # TODO: decode data
    if @buffer
      @buffer << data
      addr, rest = @buffer.split("\n", 2)
      if rest && rest.length > 0
        host, port = addr.split(":")
        port = port.nil? ? 80 : port.to_i
        @connection = EventMachine.connect(host, port, RemoteConnection)
        @connection.server = self
        @connection.send_data(rest) if rest.length > 0
        @buffer = nil
      end
    else
      @connection.send_data(data) if data && data.length > 0
    end
  rescue
    @connection.close_connection if @connection
    close_connection
  end

  def unbind
    @connection.close_connection if @connection
  end
end

EventMachine.run do
  puts "Starting server at 0.0.0.0:#{REMOTE_SERVER_PORT}"
  EventMachine.start_server('0.0.0.0', REMOTE_SERVER_PORT, RemoteServer)
end
```

### 使い方

リポジトリはこちらに上げました。[socks-tunnel-demo](https://github.com/cctiger36/socks-tunnel-demo)

* まずは一番上のホストとポートを設定します。
* ローカルで `bundle exec ruby local.rb` を実行します。
* リモートサーバーで `bundle exec ruby remote.rb` を実行します。
* ブラウザのプロキシの設定にローカルサーバーを設定します。Mac ならこんな感じです。
{% img /images/mac-proxy-settings.png %}

これでブラウザはプロキシ経由で外にアクセスできるはずです。

### TODO

ここまで作ったものは実際には全く使いものにならないです。orz

何故なら急いで書いたから、肝心な暗号化の部分はまだ実装されていません（TODO が書いてるところ）。
今のローカルからリモートへの通信は Firewall に丸見えです。簡単に探知され、ゲームオーバーになります。

暗号化については連休中で補完できればと思います。本当に申し訳ございません。m(＿ ＿)m

## 明日

【その2】ドリコム Adevent Calendar 2015 25日目は ericinderbuchtvontokio さんです。
