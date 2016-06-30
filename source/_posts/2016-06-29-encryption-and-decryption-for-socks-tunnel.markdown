---
layout: post
title: "自作 socks tunnel の暗号化について"
date: 2016-06-29 17:42:52 +0900
comments: true
categories: 
---

前回の [Firewall を貫くツールを自作してみた]({% post_url 2015-12-23-self-made-socks-tunnel %}) の続きです。今回は暗号化の部分を補完します。

基本的は SSL/TLS のデータ送受信の段階と同じ[共通鍵暗号](https://www.wikiwand.com/ja/%E5%85%B1%E9%80%9A%E9%8D%B5%E6%9A%97%E5%8F%B7)を使えばいいです。  
今回はとりあえず一番普通の AES-256-CBC で暗号化しようと思ういます。(アルゴリズムは簡単に変えられます)

Ruby でやるなら [OpenSSL::Cipher](http://ruby-doc.org/stdlib-2.3.0/libdoc/openssl/rdoc/OpenSSL/Cipher.html) を使えば簡単に実装できます。

暗号化と復号化用のクラスはこんな感じです。基本的は Ruby のドキュメント通りです。

```ruby coder.rb
require "openssl"

CIPHER = "AES-256-CBC"
SALT = "V\x11\x97\xA6r\xEF[\xFE"
PASSWORD = "mypassword"

class Coder
  def initialize
    cipher = OpenSSL::Cipher.new(CIPHER)
    key_iv = OpenSSL::PKCS5.pbkdf2_hmac_sha1(PASSWORD, SALT, 2000, cipher.key_len + cipher.iv_len)
    @key = key_iv[0, cipher.key_len]
    @iv = key_iv[cipher.key_len, cipher.iv_len]

    @encoder = OpenSSL::Cipher.new(CIPHER)
    @encoder.encrypt
    @encoder.key = @key

    @decoder = OpenSSL::Cipher.new(CIPHER)
    @decoder.decrypt
    @decoder.key = @key
  end

  def encode(data)
    @encoder.iv = @iv
    @encoder.update(data) + @encoder.final
  end

  def decode(data)
    @decoder.iv = @iv
    @decoder.update(data) + @decoder.final
  end
end
```

キーと IV を手元で作っても構わないが、ドキュメント通りに [PBKDF2](https://www.wikiwand.com/en/PBKDF2) を使って、パスワードとソルトから生成したほうが正しい道と思います。  
もちろんパスワードとソルトをソースコードに書くのも良くないですけど、ここは一旦置いといて、とりあえず暗号化と復号化ができればいいです。

```sh
irb
2.3.0 :001 > require_relative "coder"
2.3.0 :002 > coder = Coder.new
 => #<Coder:0x007ffa4a04b1d0 @key="\xE4\xC6\xDF\x80\xE7\x81k\x7F\b@\ezo\x18@~U}\xE9\xA9\xE4++\xAE\x92X\x81\xE8\tu\xD6(", @iv="S\x8C\xC6\xB8\x97l\xACu\xD4O\xB7\xEF\xAA\x11\xCB\xD3", @encoder=#<OpenSSL::Cipher:0x007ffa4a04b108>, @decoder=#<OpenSSL::Cipher:0x007ffa4a04b0e0>>
2.3.0 :003 > encoded = coder.encode("test12345")
 => ",\x81\xFD\xEE\v\x91fr\xA1eC\xECR:\x00\xF0"
2.3.0 :004 > coder.decode(encoded)
 => "test12345"
```

後は前回残した TODO のところにこの `Coder` を適用すればいいです。

ここでちょっとハマったところは、EventMachine::Connection#send_data はメッセージをまるごと送信するとは限らないです。途切れ途切れになるかもしれません。  
暗号化しない場合は特に問題ないだけど、暗号化すると、どこからどこまでは１つのメッセージなのかがわからないと、ちゃんと複合できなくなります。  
だから人為的に区切りのものをメッセージの間に入れることになりました。

```ruby
def send_encoded_data(data)
  return if data.nil? || data.empty?
  send_data(@coder.encode(data))
  send_data("DRECOMADVENTCALENDAR")  # 文字列にするかバイナリにするかはお好きにどうぞ
end
```

通信内容はこんな感じになります。

```
HOST:PORT (Encoded)
DRECOMADVENTCALENDAR <- Delimiter
DATA (Encoded)
DRECOMADVENTCALENDAR <- Delimiter
DATA (Encoded)
DRECOMADVENTCALENDAR <- Delimiter
```

複合するところも一旦バッファに入れて、区切りのところまで切り取って順番に復号します。

```ruby
def receive_data(data)
  return if data.nil? || data.empty?
  @buffer << data
  loop do
    fore, rest = @buffer.split("DRECOMADVENTCALENDAR", 2)
    break unless rest
    server.send_data(@coder.decode(fore))
    @buffer = rest
  end
end
```

これで通信が暗号化され、安心で使えるようになりました。＼(＾▽＾)／  
作りはまだ雑だけど、もう実用できると思います。

具体的なコードはまた [Github](https://github.com/cctiger36/socks-tunnel-demo) のほうへどうぞ。
