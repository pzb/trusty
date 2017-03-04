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
122 => :DISALLOWED_ENHKEY_USAGE
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
  asn1.value.each do |elem|
    inf = {}
    if not elem.is_a? OpenSSL::ASN1::Sequence
      print "Error C: #{elem.class}\n"
      return
    end
    if elem.value.count != 2
      print "Error D: #{elem.value.count}\n"
      return
    end
    x = elem.value.take(2)
    if not x[0].is_a? OpenSSL::ASN1::ObjectId
      print "Error E: #{x[0].class}\n"
      return
    end
    inf[:oid] = x[0].value
    if not x[1].is_a? OpenSSL::ASN1::Sequence
      print "Error F: #{x[1].class}\n"
      return
    end
    if x[1].value.count != 1
      print "Error G: #{x[1].value.count}\n"
      return
    end
    if not x[1].value.first.is_a? OpenSSL::ASN1::Sequence
      print "Error H: #{x[1].value.first.class}\n"
      return
    end
    if x[1].value.first.value.count != 2
      print "Error I: #{x[1].value.first.count}\n"
      return
    end
    y = x[1].value.first.value.take(2)
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
                print "Error vA: #{asn1.class}\n"
                return
        end
        asn1.value.each do |elem|
                if not elem.is_a? OpenSSL::ASN1::ObjectId
                        print "Error vB: #{elem.class}\n"
                        return
                end
                extras << elem.value
        end
        extras
end

module PKCS7
  # https://tools.ietf.org/html/rfc2315#section-7
  class ContentInfo
    attr_reader :contentType
    attr_reader :content
    def initialize(asn1)
      if not asn1.is_a? OpenSSL::ASN1::Sequence
        raise "Error Aci: #{asn1.class}"
      end
      if asn1.value.count < 1 || asn1.value.count > 2
        raise "Error B: #{asn1.count}"
      end
      seq = asn1.value.take(2)
      if not seq[0].is_a? OpenSSL::ASN1::ObjectId
        raise "Error C: #{seq[0].class}"
      end
      @contentType = seq[0].value
      @content = nil
      if asn1.count == 1 # No content
        return
      end

      # content is explicitly tagged
      if not seq[1].class == OpenSSL::ASN1::ASN1Data
        raise "Error Dx: #{seq[1].class}"
      end
      if not seq[1].tag == 0
        raise "Error E: #{seq[1].tag}"
      end
      @content = seq[1].value[0]
    end
  end

  # https://tools.ietf.org/html/rfc2315#section-9.1
  class SignedData
    attr_reader :digestAlgorithms
    attr_reader :contentInfo
    attr_reader :certificates
    attr_reader :crls
    attr_reader :signerInfos

    def initialize(asn1)
      if not asn1.is_a? OpenSSL::ASN1::Sequence
        raise "Error sdA: #{asn1.class}"
      end
      if asn1.value.count < 4 || asn1.value.count > 6
        raise "Error sdB: #{asn1.count}"
      end
      seq = asn1.value.take(6)
      if !seq[0].is_a?(OpenSSL::ASN1::Integer) || seq[0].value != 1
        raise "Error sdC: #{seq[0].value}"
      end
      seq.shift # Version
      @signerInfos = seq.pop
      @digestAlgorithms = seq.shift
      @contentInfo = seq.shift
      @certificates = nil
      @crls = nil

      seq.each do |i|
        if !i.is_a?(OpenSSL::ASN1::ASN1Data)
          raise "Error sdD: #{i.class}"
        end
        case i.tag
        when 0
          @certificates = i.value
        when 1
          @crl = i.value
        else
          raise "Error sdE: #{i.tag}"
        end
      end
    end
  end
end

module CTL
  class TrustedSubject
    attr_reader :hash
    attr_reader :attributes

    def initialize(asn1)
      if not asn1.is_a? OpenSSL::ASN1::Sequence
        raise "Error tsA: #{asn1.class}"
      end
      if asn1.value.count < 1 || asn1.value.count > 2
        raise "Error tsB: #{asn1.count}"
      end
      seq = asn1.value.take(2)
      @attributes = {}
      @hash = seq[0].value.force_encoding('BINARY').bytes.map{|c| "%02x" % c}.join('')
      if seq.count > 1
        seq[1].value.each do |attr|
          if !attr.is_a?(OpenSSL::ASN1::Sequence) || attr.value.count != 2
            raise "Error TS1: #{attr}"
          end
          iseq = attr.value.take(2)
          if !iseq[0].is_a?(OpenSSL::ASN1::ObjectId)
            raise "Error TS2: #{iseq[0]}"
          end
          oid = iseq[0].oid
          if @attributes.key?(oid)
            raise "Error TS3: #{oid}"
          end
          if !iseq[1].is_a?(OpenSSL::ASN1::Set) || iseq[1].value.count != 1
            raise "Error TS4: #{iseq[1]}"
          end
          @attributes[oid] = iseq[1].value.take(1).first.value
        end
      end
    end
  end

=begin
CertificateTrustList ::= SEQUENCE {
  version CTLVersion DEFAULT v1
  subjectUsage SubjectUsage,
  listIdentifier ListIdentifier OPTIONAL,
  sequenceNumber HUGEINTEGER OPTIONAL,
  ctlThisUpdate ChoiceOfTime,
  ctlNextUpdate ChoiceOfTime OPTIONAL,
  subjectAlgorithm AlgorithmIdentifier,
  trustedSubjects TrustedSubjects OPTIONAL,
  ctlExtensions [0] EXPLICIT Extensions OPTIONAL
}

CTLVersion ::= INTEGER {v1(0)}

SubjectUsage ::= EnhancedKeyUsage

ListIdentifier ::= OCTETSTRING

TrustedSubjects ::= SEQUENCE OF TrustedSubject

TrustedSubject ::= SEQUENCE{
  subjectIdentifier SubjectIdentifier,
  subjectAttributes Attributes OPTIONAL
}

SubjectIdentifier ::= OCTETSTRING
=end

  class CertificateTrustList
    attr_reader :version # DEFAULT v1
    attr_reader :subjectUsage
    attr_reader :listIdentifier # OPTIONAL
    attr_reader :sequenceNumber # OPTIONAL
    attr_reader :thisUpdate
    attr_reader :nextUpdate # OPTIONAL
    attr_reader :subjectAlgorithm
    attr_reader :trustedSubjects # OPTIONAL
    attr_reader :extensions # OPTIONAL

    def initialize(asn1)
      if not asn1.is_a? OpenSSL::ASN1::Sequence
        raise "Error ctlA: #{asn1.class}"
      end
      if asn1.value.count < 3 || asn1.value.count > 9
        raise "Error ctlB: #{asn1.count}"
      end
      @listIdentifier = nil
      seq = asn1.value.take(8)
      if seq[0].is_a?(OpenSSL::ASN1::Integer)
        @version = seq.shift.value
      else
        @version = 0
      end
      @subjectUsage = validExtra(seq.shift)

      if seq[0].is_a?(OpenSSL::ASN1::OctetString)
        @listIdentifier = seq.shift
        @listIdentifier = @listIdentifier.value.force_encoding("UTF-16LE").encode("UTF-8").chomp("\0")
      end

      if seq[0].is_a?(OpenSSL::ASN1::Integer)
        @sequenceNumber = seq.shift.value
      else
        @sequenceNumber = nil
      end

      @thisUpdate = seq.shift
      if !@thisUpdate.is_a?(OpenSSL::ASN1::UTCTime)
        raise "Error ctlC: #{@thisUpdate}"
      end
      @thisUpdate = @thisUpdate.value

      if seq[0].is_a?(OpenSSL::ASN1::UTCTime)
        @nextUpdate = seq.shift.value
      end

      @subjectAlgorithm = seq.shift

      # this could be either a trustedSubjects or a ctlExtensions
      if seq[0].is_a?(OpenSSL::ASN1::Sequence)
        # This is a seq, is first thning an OCTET STRING or Object Id
        first_thing = seq[0].value[0]
        if first_thing.value[0].is_a?(OpenSSL::ASN1::OctetString)
          @trustedSubjects = seq.shift.value
        end
      end

      @extensions = seq.shift

      if !seq.empty?
        raise "Error ctlD: Extra elements #{seq}"
      end
    end
  end
end

def parseSTL(asn1)
  p7 = PKCS7::ContentInfo.new(asn1)
  if p7.contentType != "pkcs7-signedData"
    raise "Error pstlA: #{p7.contentType}"
  end
  signed_data = PKCS7::SignedData.new(p7.content)
  signed_content= PKCS7::ContentInfo.new(signed_data.contentInfo)
  if signed_content.contentType != "1.3.6.1.4.1.311.10.1" # szOID_CTL
    raise "Error pstlB: #{p7.contentType}"
  end

  ctl = CTL::CertificateTrustList.new(signed_content.content)

  # Make sure this is a Root List
  if ctl.subjectUsage != ["1.3.6.1.4.1.311.10.3.9"] # szOID_ROOT_LIST_SIGNER
    raise "Error pstlC: #{ctl.subjectUsage}"
  end

  entries = {}

  ctl.trustedSubjects.each do |entry|
    ts = CTL::TrustedSubject.new(entry)
    if entries.key?(ts.hash)
      raise "Error pstlD: #{ts.hash}"
    end
    properties = {}
    ts.attributes.each do |oid, val|
      if oid[0..21] != "1.3.6.1.4.1.311.10.11."
        raise "Error pstlE: #{oid}"
      end
      prop = oid.split('.').last.to_i
      if PROPS.has_key? prop
        prop = PROPS[prop]
      end
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
      elsif prop == :DISALLOWED_ENHKEY_USAGE
        val = validExtra(OpenSSL::ASN1.decode(val))
      else
        raise "Error pstlF: Unparsed property #{prop}\n"
      end
      properties[prop] = val
    end
    entries[ts.hash] = properties
  end
  entries
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
