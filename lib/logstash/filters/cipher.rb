# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "logstash/json"
require "openssl"
require "json"





# This filter parses a source and apply a cipher or decipher before
# storing it in the target.

class LogStash::Filters::Cipher < LogStash::Filters::Base
  config_name "cipher"



  # the field to perform the partial encryption
  config :value_regex, :validate => :string, :required => false

  # The parameter that will match the field to crypt based on regex expression
  config :key_regex, :validate => :string, :default => "", :required => true

  # the field to perform encryptiong everywhere it appears
  # config :field_to_crypt, :validate => :string, :default  => ""

  # The field to perform filter
  #
  # Example, to use the @message field (default) :
  # [source,ruby]
  #     filter { cipher { source => "message" } }
  config :source, :validate => :string, :default => "message"

  # The name of the container to put the result
  #
  # Example, to place the result into crypt :
  # [source,ruby]
  #     filter { cipher { target => "crypt" } }
  config :target, :validate => :string, :default => "message"

  # Do we have to perform a `base64` decode or encode?
  #
  # If we are decrypting, `base64` decode will be done before.
  # If we are encrypting, `base64` will be done after.
  #
  config :base64, :validate => :boolean, :default => true

  # The key to use
  #
  # NOTE: If you encounter an error message at runtime containing the following:
  #
  # "java.security.InvalidKeyException: Illegal key size: possibly you need to install
  # Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files for your JRE"
  #
  # Please read the following: https://github.com/jruby/jruby/wiki/UnlimitedStrengthCrypto
  #
  config :path_to_key, :validate => :string

  # The key size to pad
  #
  # It depends of the cipher algorithm. If your key doesn't need
  # padding, don't set this parameter
  #
  # Example, for AES-128, we must have 16 char long key. AES-256 = 32 chars
  # [source,ruby]
  #     filter { cipher { key_size => 16 }
  #
  config :key_size, :validate => :number, :default => 16

  # The character used to pad the key
  config :key_pad, :default => "\0"

  # The cipher algorithm
  #
  # A list of supported algorithms can be obtained by
  # [source,ruby]
  #     puts OpenSSL::Cipher.ciphers
  config :algorithm, :validate => :string, :required => true

  # Encrypting or decrypting some data
  #
  # Valid values are encrypt or decrypt
  config :mode, :validate => :string, :required => true

  # Cipher padding to use. Enables or disables padding.
  #
  # By default encryption operations are padded using standard block padding
  # and the padding is checked and removed when decrypting. If the pad
  # parameter is zero then no padding is performed, the total amount of data
  # encrypted or decrypted must then be a multiple of the block size or an
  # error will occur.
  #
  # See EVP_CIPHER_CTX_set_padding for further information.
  #
  # We are using Openssl jRuby which uses default padding to PKCS5Padding
  # If you want to change it, set this parameter. If you want to disable
  # it, Set this parameter to 0
  # [source,ruby]
  #     filter { cipher { cipher_padding => 0 }}
  config :cipher_padding, :validate => :string

  # The initialization vector to use (statically hard-coded). For
  # a random IV see the iv_random_length property
  #
  # NOTE: If iv_random_length is set, it takes precedence over any value set for "iv"
  #
  # The cipher modes CBC, CFB, OFB and CTR all need an "initialization
  # vector", or short, IV. ECB mode is the only mode that does not require
  # an IV, but there is almost no legitimate use case for this mode
  # because of the fact that it does not sufficiently hide plaintext patterns.
  #
  # For AES algorithms set this to a 16 byte string.
  # [source,ruby]
  #     filter { cipher { iv => "1234567890123456" }}
  #
  # Deprecated: Please use `iv_random_length` instead
  config :path_to_iv, :validate => :string, :deprecated => "Please use 'iv_random_length'"

  # Force an random IV to be used per encryption invocation and specify
  # the length of the random IV that will be generated via:
  #
  #       OpenSSL::Random.random_bytes(int_length)
  #
  # If iv_random_length is set, it takes precedence over any value set for "iv"
  #
  # Enabling this will force the plugin to generate a unique
  # random IV for each encryption call. This random IV will be prepended to the
  # encrypted result bytes and then base64 encoded. On decryption "iv_random_length" must
  # also be set to utilize this feature. Random IV's are better than statically
  # hardcoded IVs
  #
  # For AES algorithms you can set this to a 16
  # [source,ruby]
  #     filter { cipher { iv_random_length => 16 }}
  config :iv_random_length, :validate => :number

  # If this is set the internal Cipher instance will be
  # re-used up to @max_cipher_reuse times before being
  # reset() and re-created from scratch. This is an option
  # for efficiency where lots of data is being encrypted
  # and decrypted using this filter. This lets the filter
  # avoid creating new Cipher instances over and over
  # for each encrypt/decrypt operation.
  #
  # This is optional, the default is no re-use of the Cipher
  # instance and max_cipher_reuse = 1 by default
  # [source,ruby]
  #     filter { cipher { max_cipher_reuse => 1000 }}
  config :max_cipher_reuse, :validate => :number, :default => 1

  def crypto_map(red_key,red_iv,key, index_start, index_end,my_hash_map,event)


    if my_hash_map.empty?
      printf("im empty and i add new things \n")
      my_hash_map["#{red_key}"]  = [{field: key, start: index_start,end: index_end}]
      printf("here is the result: #{my_hash_map}\n")
    else
      my_hash_map.each {|first_key, value|
        printf("here im looking if the root key is the same, so i can add inside\n ")
        my_hash_map["#{first_key}"] << {field: key, start: index_start,end: index_end} if first_key == red_key
        printf("this is the map after doing this #{my_hash_map}")
      }
      #printf("same key, i append inside and this is the result #{my_hash_map} \n")
    end
    if event.get("cipher_info") != nil
      printf("cipher was already added by another cipher before! here's what I have: #{event.get("cipher_info")} \n")
      second_hash = event.get("cipher_info")
      # my_hash_map["#{red_key}"]  = [{field: key, start: index_start,end: index_end}]
      my_hash_map.merge(second_hash)
    end

    return my_hash_map
  end



  def crypto(event, key, value)

    if (event.get(@source).nil? || event.get(@source).empty?)
      #@logger.debug("Event to filter, event 'source' field: " + @source + " was null(nil) or blank, doing nothing")
      return
    end
    if value.to_s == ""
      return  ""
    end
    data = value.to_s #cambio la source, cambiarlo ciclicamente
    # printf("data is (deve essere uguale a value) : #{data} and the key is #{key}\n")
    if @mode == "decrypt"
      data =  Base64.strict_decode64(data) if @base64 == true

      if !@iv_random_length.nil?
        @random_iv = data.byteslice(0,@iv_random_length)
        data = data.byteslice(@iv_random_length..data.length)
      end

    end

    if !@iv_random_length.nil? and @mode == "encrypt"
      @random_iv = OpenSSL::Random.random_bytes(@iv_random_length)
    end

    # if iv_random_length is specified, generate a new one
    # and force the cipher's IV = to the random value
    if !@iv_random_length.nil?
      @cipher.iv = @random_iv
    end

    result = @cipher.update(data) + @cipher.final
    #printf("questo è il result dopo cipher.update + cipher final : #{result}\n")

    if @mode == "encrypt"

      # if we have a random_iv, prepend that to the crypted result
      if !@random_iv.nil?
        result = @random_iv + result
      end

      result =  Base64.strict_encode64(result).encode("utf-8") if @base64 == true
      #printf("ho matchato! #{key}:#{value} this is the result after encoding #{result}\n")

    end

  rescue => e
    @logger.warn("Exception catch on cipher filter", :event => event, :error => e)

    # force a re-initialize on error to be safe
    init_cipher

  else
    @total_cipher_uses += 1
    #result = result.force_encoding("utf-8") if @mode == "decrypt"
    result = result.force_encoding("utf-8") if @mode == "decrypt"


    #event.set(key,result)

    #Is it necessary to add 'if !result.nil?' ? exception have been already catched.
    #In doubt, I keep it.
    filter_matched(event) if !result.nil?

    if !@max_cipher_reuse.nil? and @total_cipher_uses >= @max_cipher_reuse
      #@logger.debug("max_cipher_reuse["+@max_cipher_reuse.to_s+"] reached, total_cipher_uses = "+@total_cipher_uses.to_s)
      init_cipher
    end

    return result
  end #def crypto


  def visit_json(event,parent, myHash)

    my_hash_map = {}

    myHash.each do |key, value|
      value.is_a?(Hash) ? visit_json(event,key, value) :

        if @value_regex != nil

          if (/#{@key_regex}/ =~ key.to_s) != nil && (/#{@value_regex}/ =~ value.to_s) != nil && !value.is_a?(Hash)
            # printf("this is the matched value as index  #{(/#{@value_regex}/ =~ value.to_s)}\n")
            aux = (/#{@value_regex}/.match(value)).to_s # aux will be the matched value.

            index_start = (/#{@value_regex}/ =~ value.to_s) # where to start.
            tot_value = value.to_s.length
            wordEndIndex = -(tot_value - (index_start + aux.length)) # where it finishes from the end.

            test = crypto_map(@path_to_key,@path_to_iv,key,index_start,wordEndIndex,my_hash_map,event)

            printf("the word to crypt start at index : #{index_start}\n")
            printf("this is the value lenght: #{tot_value}\n")
            printf("this is the index for end of the word in all the value field: #{wordEndIndex}\n")
            printf("this is the object : #{test}\n")


            event.set("cipher_info", test)
            printf("this is the new field: #{event.get("cipher_info")}\n")

            #printf("this is the matched value as the word #{aux}\n")
            result3 = crypto(event, key, aux)
            #printf("this is the result of the encryption #{result3}\n")
            new_value = value.gsub(aux, result3)
            #printf("this is value at the end  #{new_value}\n")
            myHash[key] = new_value





          end
        else
          if (/#{@key_regex}/ =~ key.to_s) != nil

            result2 = crypto(event, "#{key}", "#{value}")
            myHash[key] = result2
          else
            #printf("not matched\n")
          end

        end

    end
  end





  def register
    require 'base64' if @base64
    @semaphore = Mutex.new
     @semaphore.synchronize {
       init_cipher
     }
  end # def register

  def filter(event)

@semaphore.synchronize {


    #If decrypt or encrypt fails, we keep it it intact.
    begin

      if @key_regex == "message" # keep the previous cipher, crypt everything.
        my_source = event.get(@source)
        # printf("this is source #{my_source}\n")
        crypt_all = crypto(event, @key_regex, my_source)
        # printf("this is crypt_All #{crypt_all}\n")
        event.set("message", crypt_all)
        # printf("ho aggiunto il crypt al messaggio-clone\n")

      else
        my_source = event.get(@source)
        #printf("questa è la source prima dell'hash #{my_source}\n")
        parsed = LogStash::Json.load(my_source)
        #printf("this is my hash : #{parsed}")
        message = visit_json(event,nil, parsed)

        event.set("message", message.to_json)
        #printf("Non sono il clone, ho aggiunto crypt al messaggio!\n")
      end
    end
  }
  end # def filter

  def init_cipher
    red = File.read(@path_to_key)
    #printf("this is what i red #{red}\n")
    red_iv = File.read(@path_to_iv)
    #printf("this is the iv i red #{red_iv}")

    # config = ParseConfig.new(@path_to_key)
    # #printf("this is config #{config}")
    # key_red = config["key"]
    # printf("this is the key #{key_red}\n")
    # iv_red = config["iv"]


    if !@cipher.nil?
      @cipher.reset
      @cipher = nil
    end

    @cipher = OpenSSL::Cipher.new(@algorithm)

    @total_cipher_uses = 0

    if @mode == "encrypt"
      @cipher.encrypt
    elsif @mode == "decrypt"
      @cipher.decrypt
    else
      @logger.error("Invalid cipher mode. Valid values are \"encrypt\" or \"decrypt\"", :mode => @mode)
      raise "Bad configuration, aborting."
    end

    # if red.length != @key_size
    #   @logger.debug("key length is " + key_red.length + ", padding it to " + @key_size.to_s + " with '" + @key_pad.to_s + "'")
    #   red = red[0,@key_size].ljust(@key_size,@key_pad)
    # end

    # red = red[0,@key_size].ljust(@key_size,@key_pad)

    @cipher.key = red

    # if !@path_to_iv.nil? and !@path_to_iv.empty? and @iv_random_length.nil?
    #   @cipher.iv = iv_red if @path_to_iv

    @cipher.iv = red_iv

    # elsif !@iv_random_length.nil?
    #   @logger.debug("iv_random_length is configured, ignoring any statically defined value for 'iv'", :iv_random_length => @iv_random_length)
    # else
    #   raise "cipher plugin: either 'iv' or 'iv_random_length' must be configured, but not both; aborting"
    # end

    @cipher.padding = @cipher_padding if @cipher_padding

    @logger.debug("Cipher initialisation done", :mode => @mode, :path_to_key => red, :iv_random => @iv_random, :cipher_padding => @cipher_padding)
  end # def init_cipher

end # class LogStash::Filters::Cipher
