#!/usr/bin/env ruby
require 'bindata'
require 'pp'
require 'openssl'
require 'csv'
require 'base64'
$stdout.sync = true

class SerializedEntry < BinData::Record
  endian :little
  uint32 :id
  uint32 :encodingType
  uint32 :len
  string :value_data, :read_length => :len
end

class SerializedCertStoreParser < BinData::Record
  endian :little
  uint32 :version, :assert => 0
  uint32 :fileType, :assert => 0x54524543
  array  :raw_entries, :type => SerializedEntry, :read_until => :eof
end

class SerializedCertStore
	attr_reader :certGroups

	def initialize(io)
		sst = SerializedCertStoreParser.read(io)
		@certGroups = []
		elementList = []
		state = :el
		sst.raw_entries.each do |e|
			if state == :el
				if e.id == 0x0
					if e.encodingType != 0x0
						print "Bad encodingType for endMarkerElement\n"
					end
					if e.len != 0x0
						print "Bad length for endMarkerElement\n"
					end
					state = :eme
					next
				elsif e.id == 0x00000020
					state = :ce
					# Fall through to process cert
				else
					if e.encodingType != 0x1
						print "Bad encodingType for SerializedCertificateEntry\n"
					end
					elementList << e
					next
				end
			end
			if state != :ce
				print "Data past EME"
			end
			if e.id != 0x20
				print "Bad id for SerializedCertificateEntry\n"
				pp e.id
			end
			if e.encodingType != 0x1
				print "Bad encodingType for SerializedCertificateEntry\n"
			end
			c = OpenSSL::X509::Certificate.new(e.value_data)
			@certGroups << {:props => elementList, :cert => c}
			elementList = []
			state = :el
		end
	end
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

io = File.open(ARGV[0], 'rb')
sst = SerializedCertStore.new(io)
data = []
sst.certGroups.each do |cg|
	props = {}
	cg[:props].each do |e|
		case e.id
		when 11
			str = e.value_data.force_encoding('UTF-16LE').encode('UTF-8')
			if str[0] == "\u{200E}"
				str = str[1..-1]
			end
			if str[-1] == "\u{0000}"
				str = str[0..-2]
			end
			props[:name] = str
		when 9
			props[:keyUsage] = validExtra(OpenSSL::ASN1.decode(e.value_data))
		when 3
			props[:sha1hash] = e.value_data.force_encoding('BINARY').bytes.map{|c| "%02x" % c}.join('')
		when 83
			props[:evOIDs] = validEV(OpenSSL::ASN1.decode(e.value_data))
		when 105
			props[:msOIDS] = validExtra(OpenSSL::ASN1.decode(e.value_data))
		else
			print "Error: Unknown ID #{e.id}\n"
			props[e.id] = OpenSSL::ASN1.decode(e.value_data)
		end	
	end
	props[:cert] = cg[:cert]
	data << props
end

data.each do |d|
	c = d[:cert]
  s = c.subject.to_der
  puts "# " + c.subject.to_s(OpenSSL::X509::Name::RFC2253 & ~4).force_encoding("UTF-8")
  puts Base64.strict_encode64(s)
end

