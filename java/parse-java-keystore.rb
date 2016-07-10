#!/usr/bin/env ruby
require 'base64'
require 'bindata'
require 'openssl'
$stdout.sync = true

class KeyStoreEntry < BinData::Record
  endian :big
  hide :alias_len, :cert_type_len, :cert_len
  int32 :tag, :assert => 2
  int16 :alias_len
  string :cert_alias, :read_length => :alias_len
  int64 :timestamp
  int16 :cert_type_len
  string :cert_type, :read_length => :cert_type_len, :assert => "X.509"
  int32 :cert_len
  string :cert, :read_length => :cert_len
end

class KeyStoreParser < BinData::Record
  endian :big
  hide :rest
  uint32 :magic, :assert => 0xfeedfeed
  int32 :version, :assert => 2
  int32 :entry_count
  array :raw_entries, :type => KeyStoreEntry, :initial_length => :entry_count
  string :keyed_sha1, :read_length => 20
  rest :rest, :assert => ""
end

class JavaKeyStore
	attr_reader :certs
	def initialize(io)
		ks = KeyStoreParser.read(io)
		@certs = []
		ks.raw_entries.each do |e|
			cert = {}
			cert[:alias] = e.cert_alias
			cert[:type] = e.cert_type
			cert[:created] = Time.at(e.timestamp / 1000)
			cert[:cert] = OpenSSL::X509::Certificate.new(e.cert)
			@certs << cert
		end
	end
end
		
			

io = File.open(ARGV[0], 'rb')
ks = JavaKeyStore.new(io)

ks.certs.each do |cert_info|
	c = cert_info[:cert]
  puts "# " + c.subject.to_s(OpenSSL::X509::Name::RFC2253 & ~4).force_encoding("UTF-8")
  puts Base64.strict_encode64(c.subject.to_der)
end
