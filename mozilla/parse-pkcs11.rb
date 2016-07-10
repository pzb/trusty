#!/usr/bin/env ruby
require 'openssl'
require 'base64'
$stderr.sync = true

def parse_certdata(io)
  certdata = {}
  state = :single_line
  multiline_buff = ''
  multiline_name = nil
  curr_cert = {}
  io.each_line do |line|
    line.chomp!

    # If in middle of a multiline section, process and then move to next
    # line
    if state == :multiline
      if line =~ /^\s*END/
        chars = multiline_buff.split(/\\/)
        if chars[0] != ""
          $stderr.puts "ML Error!"
        end
        chars.shift
        curr_cert[multiline_name] = chars.map{|c| c.to_i(8).chr}.join('')
        state = :single_line
        multiline_buff = ''
        next
      else
        multiline_buff += line
        next
      end
    end
    
    # Remove comments and blank lines and delete broken encoding
    begin
      next if line =~ /^\s*#/
    rescue ArgumentError
      line = line.encode('UTF-8', :invalid => :replace, :undef => :replace)
      next if line =~ /^\s*#/
    end
    next if line =~ /^\s*$/

    attr, type, rest = line.split(/\s+/, 3)

    # Begining marker; useless to us
    if attr == "BEGINDATA" || attr == "CVS_ID"
      next
    end


    if attr !~ /^CKA_/
      $stderr.puts "Unknown attribute name #{attr}"
    end

    attr_name = attr[4..-1].downcase.to_sym

    case type
    # Basic types
    when "CK_BBOOL"
      if rest == "CK_TRUE"
        curr_cert[attr_name] = true
      elsif rest == "CK_FALSE"
        curr_cert[attr_name] = false
      else
        $stderr.puts "Bad boolean value: #{rest}"
      end
      next
    when "MULTILINE_OCTAL"
      multiline_name = attr_name
      state = :multiline
      next
    when "UTF8"
      if rest[0] != '"' || rest[-1] != '"'
        $stderr.puts "Bad UTF8 value: #{rest}"
      end
      curr_cert[attr_name] = rest[1..-2]
      next

    # PKCS11 Enums
    when "CK_OBJECT_CLASS"
      if attr_name != :class
        $stderr.puts "Bad attribute! #{attr_name}"
      end
      if rest !~ /^CKO_/
        $stderr.puts "Bad class! #{rest}"
      end
      if curr_cert.key?(:class)
        currclass = curr_cert[:class]
        if !certdata.key?(currclass)
          certdata[currclass] = []
        end
        certdata[currclass] << curr_cert
      end
      curr_cert = {}
      tmp = rest[4..-1].downcase
      if tmp == "netscape_trust"
        tmp = "nss_trust"
      end
      curr_cert[attr_name] = tmp 
      next
    when "CK_CERTIFICATE_TYPE"
      if attr_name != :certificate_type
        $stderr.puts "Bad attribute! #{attr_name}"
      end
      if rest !~ /^CKC_/
        $stderr.puts "Bad type! #{rest}"
      end
      curr_cert[attr_name] = rest[4..-1]
      next
    when "CK_TRUST"
      if attr_name.to_s !~ /^trust_/
        $stderr.puts "Bad attribute! #{attr_name}"
      end
      if rest =~ /\ACKT_((NETSCAPE|NSS)_TRUST_UNKNOWN|NSS_MUST_VERIFY_TRUST)\z/
        # Not trusted for this use
        curr_cert[:neutral] = true
        next
      end

      # Completely distrusted
      if rest =~ /\ACKT_(NETSCAPE_UNTRUSTED|NSS_NOT_TRUSTED)\z/
        curr_cert[:distrusted] = true
        next
      end
      # Delegator means trusted
      if rest !~ /\ACKT_(NETSCAPE|NSS)_(VALID|(VALID|TRUSTED)_DELEGATOR)\z/
        $stderr.puts "Bad value! #{rest}"
      end
      if !curr_cert.key?(:trust)
        curr_cert[:trust] = []
      end
      curr_cert[:trust] << attr_name.to_s[6..-1]
      next

    else
      $stderr.puts "Unknown type: #{type}"
    end
    $stderr.puts "Processing #{attr} of type #{type} with #{rest}"
  end
  if curr_cert.key?(:class)
    currclass = curr_cert[:class]
    if !certdata.key?(currclass)
      certdata[currclass] = []
    end
    certdata[currclass] << curr_cert
  end
  certdata
end


io = File.open(ARGV[0], 'r:utf-8')
certdata = parse_certdata(io)
io.close

certs = {}

# First, create a hash indexed by cert SHA1 and ensure no duplicates
certdata["certificate"].each do |c|
  c[:cert_sha1] = (OpenSSL::Digest::SHA1.new << c[:value]).digest
  c[:cert_md5] = (OpenSSL::Digest::MD5.new << c[:value]).digest
  c[:cert] = OpenSSL::X509::Certificate.new c[:value]
  c.delete :value
  c[:issuer] = OpenSSL::X509::Name.new c[:issuer]
  if certs.key?(c[:cert_sha1])
    $stderr.puts "Duplicate certificate!"
  end
  certs[c[:cert_sha1]] = c
end

# Now assign trust to the certificates after matching trust object to cert
# object
certdata["nss_trust"].each do |o|
  if !(o.key?(:trust) || o.key?(:distrusted) || o.key?(:neutral))
    $stderr.puts "Missing trust data for #{o[:label]}!"
    next
  end
  if o.key?(:trust) && o.key?(:distrusted)
    $stderr.puts "Both trusted and distrusted!"
  end
  if o.key?(:issuer)
    o[:issuer] = OpenSSL::X509::Name.new o[:issuer]
  end
  k = o[:cert_sha1_hash]
  if !certs.key?(k)
    if o.key?(:trust)
      $stderr.puts "Unknown trust!"
    end
    next
  end
  l = o[:label]
  if o[:label] != certs[k][:label]
    $stderr.puts "Label mismatch! (#{l})"
  end
  if o.key?(:issuer) && (o[:issuer] != certs[k][:issuer])
    $stderr.puts "Issuer mismatch! (#{l})"
  end
  if o.key?(:serial_number) && (o[:serial_number] != certs[k][:serial_number])
    $stderr.puts "Serial mismatch! (#{l})"
  end
  if o[:cert_md5_hash] != certs[k][:cert_md5]
    $stderr.puts "MD5 mismatch! (#{l})"
  end
  if o.key?(:trust)
    certs[k][:trust] = o[:trust]
  end
  if o.key?(:distrusted)
    certs.delete k
  end
end

certs.each do |k, x|
  next if x[:trust].nil? || x[:trust].empty?
  c = x[:cert]
  s = c.subject.to_der
  puts "# " + c.subject.to_s(OpenSSL::X509::Name::RFC2253 & ~4).force_encoding("UTF-8")
  puts Base64.strict_encode64(s)
end
