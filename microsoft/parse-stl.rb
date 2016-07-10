#!/usr/bin/env ruby
require 'openssl'
require 'base64'

PROPS = {
3 => :SHA1_HASH,
9 => :ENHKEY_USAGE,
11 => :FRIENDLY_NAME,
20 => :KEY_IDENTIFIER,
29 => :SUBJECT_NAME_MD5_HASH,
83 => :ROOT_PROGRAM_CERT_POLICIES,
98 => :AUTH_ROOT_SHA256_HASH,
104 => :DISALLOWED_FILETIME,
105 => :ROOT_PROGRAM_CHAIN_POLICIES,
122 => :unknown
}

def FriendlyName(str)
	str = str.force_encoding('UTF-16LE').encode('UTF-8')
	if str[0] == "\u{200E}"
		str = str[1..-1]
	end
	if str[-1] == "\u{0000}"
		str = str[0..-2]
	end
end

def validEV(asn1)
	ev_infos = []
	if not asn1.is_a? OpenSSL::ASN1::Sequence
		print "Error A: #{asn1.class}\n"
		return
	end
	asn1.each do |elem|
		inf = {}
		if not elem.is_a? OpenSSL::ASN1::Sequence
			print "Error C: #{elem.class}\n"
			return
		end
		if elem.count != 2
			print "Error D: #{elem.count}\n"
			return
		end
		x = elem.take(2)
		if not x[0].is_a? OpenSSL::ASN1::ObjectId
			print "Error E: #{x[0].class}\n"
			return
		end
		inf[:oid] = x[0].value
		if not x[1].is_a? OpenSSL::ASN1::Sequence
			print "Error F: #{x[1].class}\n"
			return
		end
		if x[1].count != 1
			print "Error G: #{x[1].count}\n"
			return
		end
		if not x[1].first.is_a?	OpenSSL::ASN1::Sequence
			print "Error H: #{x[1].first.class}\n"
			return
		end
		if x[1].first.count != 2
			print "Error I: #{x[1].first.count}\n"
			return
		end
		y = x[1].first.take(2)
		if not y[0].is_a? OpenSSL::ASN1::ObjectId
			print "Error J: #{y[0].class}\n"
			return
		end
		if y[0].value != "1.3.6.1.4.1.311.60.1.1"
			print "Error K: #{y[0].value}\n"
			return
		end
		if not y[1].is_a? OpenSSL::ASN1::BitString
			print "Error L: #{y[1].class}\n"
			return
		end
		if y[1].value.bytes != [192]
			print "Error M: #{y[1].value}\n"
		end
		ev_infos << inf[:oid]
	end
	ev_infos
end 

def validExtra(asn1)
        extras = []
        if not asn1.is_a? OpenSSL::ASN1::Sequence
                print "Error A: #{asn1.class}\n"
                return
        end
        asn1.each do |elem|
                if not elem.is_a? OpenSSL::ASN1::ObjectId
                        print "Error B: #{elem.class}\n"
                        return
                end
                extras << elem.value
        end
        extras
end

class ContentInfo
	attr_reader :oid
	attr_reader :content
	def initialize(asn1)
		if not asn1.is_a? OpenSSL::ASN1::Sequence
			raise "Error A: #{asn1.class}"
		end
		if asn1.count != 2
			raise "Error B: #{asn1.count}"
		end
		seq = asn1.take(2)
		if not seq[0].is_a? OpenSSL::ASN1::ObjectId
			raise "Error C: #{seq[0].class}"
		end
		@oid = seq[0].value
		if not seq[1].is_a? OpenSSL::ASN1::ASN1Data
			raise "Error D: #{seq[1].class}"
		end
		if not seq[1].value.is_a? Array
			raise "Error E: #{seq[1].value.class}"
		end
		if seq[1].value.count != 1
			raise "Error F: #{seq[1].value.count}"
		end
		@content = seq[1].value[0]
	end
end

def parseSTL(asn1)
	p7 = ContentInfo.new(asn1)
	signed_data = p7.content.take(6)
	#0: version, 1: digestAlgorithms, 2: ContentInfo, 3: Certs (opt), 4: CRLs (opt), 5: signerinfo
	content_info = ContentInfo.new(signed_data[2])
	#0: Seq, 1:, Int 2: Time, 3: Seq, 4: Seq
	#4 is the one we want
	stl = content_info.content.take(5)
	entries = stl[4]
	cert_pointers = {}
	entries.each do |entry|
		e1 = entry.take(2)
		sha1 = e1[0].value.force_encoding('BINARY').bytes.map{|c| "%02x" % c}.join('')
		if cert_pointers.has_key? sha1
			raise "Error CC: #{sha1}"
		end
		e2 =  e1[1].take(6)
		pointer = {}
		e2.each do |e3|
			e4 = ContentInfo.new(e3)
			if not e4.content.is_a? OpenSSL::ASN1::OctetString
				raise "Error AA: #{e4.content.class}"
			end
			if e4.oid[0..21] != "1.3.6.1.4.1.311.10.11."
				raise "Error CC: #{e4.oid}"
			end
			prop = e4.oid.split('.').last.to_i
			if PROPS.has_key? prop
				prop = PROPS[prop]
			end
			if pointer.has_key? prop 
				raise "Error BB: #{prop}"
			end
			val = e4.content.value
			if prop == :FRIENDLY_NAME 
				val = FriendlyName(val)
			elsif prop == :ENHKEY_USAGE
				val = validExtra(OpenSSL::ASN1.decode(val))
			elsif prop == :ROOT_PROGRAM_CHAIN_POLICIES
				val = validExtra(OpenSSL::ASN1.decode(val))
			elsif prop == :ROOT_PROGRAM_CERT_POLICIES
				val = validEV(OpenSSL::ASN1.decode(val))
			elsif prop == :SUBJECT_NAME_MD5_HASH
				val = val.each_byte.map { |b| sprintf("%02x", b) }.join
			elsif prop == :KEY_IDENTIFIER
				val = val.each_byte.map { |b| sprintf("%02x", b) }.join(":")
			elsif prop == :AUTH_ROOT_SHA256_HASH
				val = val.each_byte.map { |b| sprintf("%02x", b) }.join
      elsif prop == :DISALLOWED_FILETIME
        wtime = val.unpack('q<').first
        val = Time.at((wtime - 116444736000000000) / 10000000).utc
      elsif prop == :unknown
				val = validExtra(OpenSSL::ASN1.decode(val))
			else
				raise "Unparsed property #{prop}\n"
			end
			pointer[prop] = val
		end
		cert_pointers[sha1] = pointer
	end
	cert_pointers
end

a = OpenSSL::ASN1.decode(File.read(ARGV[0]))
p = Hash[parseSTL(a).sort]
p.each do |k, v|
  cpath = File.join(File.dirname(ARGV[0]), "..", "crts", k + ".crt")
  c = OpenSSL::X509::Certificate.new(File.read(cpath))
  s = c.subject.to_der
  puts "# " + c.subject.to_s(OpenSSL::X509::Name::RFC2253 & ~4).force_encoding("UTF-8")
  puts Base64.strict_encode64(s)
end
