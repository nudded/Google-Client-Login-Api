require "net/https"
require "uri"

module GoogleLogin
  
  
  # == ClientLogin
  # 
  # Use this Class to get an auth-token
  class ClientLogin
    
    LoginError = Class.new Exception
    
    attr_accessor :auth, :sid, :lsid
    attr_reader :captcha_url
    
    #:nodoc:
    DEFAULTS = { 
      :accountType => 'HOSTED_OR_GOOGLE' ,
      :source => 'companyName-applicationName-versionID',
      :service => 'service-identifier'
    }  
    
    # specify the :service, :source and optionally :accountType
    # 
    # [:service] the service identifier, check the google api documentation.
    #
    # [:source] the name of your application. String should be in the form
    #           "companyName-applicationName-versionID".
    #
    # [:accountType]  one of the following values: 
    #                 "GOOGLE", "HOSTED", "HOSTED_OR_GOOGLE" (default if none 
    #                 given)
    def initialize(arghash = {})
      @options = DEFAULTS.merge arghash
    end
    
    def authenticate(username, password, captcha_response = nil, &block)
      @options[:Email], @options[:Passwd] = username, password
      # set logincaptcha, captchatoken will already be set
      @options[:logincaptcha] = captcha_response if captcha_response

      response = perform_request
      
      parse_response response
      
    rescue CaptchaRequired
      if block_given?
        result = yield captcha_url
        @options[:logincaptcha] = result
        retry
      else
        raise CaptchaRequired
      end
    end
    
    private
    
    def perform_request
      request = Net::HTTP::Post.new '/accounts/ClientLogin'
      request.form_data = @options
      
      https = Net::HTTP.new 'www.google.com', 443 
      https.use_ssl = true
      
      https.request request
    end
    
    def parse_body(response_body)
      response_body.scan(/(\w+)=(.+)\n/).each do |key, value|
        instance_variable_set "@#{key.downcase}" , value
      end
    end
    
    def parse_response(response, &block)
      if response.code_type == Net::HTTPOK
        parse_body response.body
      else
        handle_error response.body, &block
      end
    end
    
    
    def handle_error(response_body)
      error_message = response_body.match(/Error=(\w+)\n/)[1].strip
      
      if error_message == "CaptchaRequired"
        @options[:logintoken] = response_body.match(/CaptchaToken=(.+)\n/)[1]
        self.captcha_url = response_body.match(/CaptchaUrl=(.+)\n/)[1]
      end
      
      raise_error_class error_message
    end
    
    def raise_error_class(error_message)
      raise self.class.const_get error_message
    rescue NameError
      self.class.const_set error_message, Class.new(LoginError)
      retry
    end
    
    def captcha_url=(url)
      @captcha_url = "http://www.google.com/accounts/" << url
    end
    
  end
  
end
