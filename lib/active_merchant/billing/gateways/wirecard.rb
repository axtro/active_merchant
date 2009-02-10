require 'base64'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class WirecardGateway < Gateway
      # Set this to true to enable XML debug output.
      attr_accessor :raw_xml_debug_output
      
      # Test server location
      TEST_URL = 'https://c3-test.wirecard.com/secure/ssl-gateway'
     
      # Live server location
      LIVE_URL = 'https://c3.wirecard.com/secure/ssl-gateway'

      # The Namespaces are not really needed, because it just tells the System, that there's actually no namespace used.
      # It's just specified here for completeness.
      ENVELOPE_NAMESPACES = {
        'xmlns:xsi' => 'http://www.w3.org/1999/XMLSchema-instance',
				'xsi:noNamespaceSchemaLocation' => 'wirecard.xsd'
			}

      PERMITTED_TRANSACTIONS = %w[ PREAUTHORIZATION AUTHORIZATION CAPTURE_AUTHORIZATION PURCHASE ]
      TRANSACTIONS_WITH_AUTHORIZATION_RESPONSE = [ :preauthorization, :authorization, :purchase]

      RETURN_CODES = %w[ ACK NOK PENDING ]

      # The countries the gateway supports merchants from as 2 digit ISO country codes.
      # WireCard supports all countries in the European Union.
      self.supported_countries = [
        'AD', 'AT', 'BE', 'BG', 'CZ', 'CY', 'DK', 'EE', 'FI', 'FR',
        'DE', 'GI', 'GR', 'HU', 'IS', 'IL', 'IE', 'IT', 'LV', 'LI',
        'LT', 'LU', 'MT', 'MC', 'NL', 'NO', 'PL', 'PT', 'RO', 'SM',
        'SK', 'SI', 'ES', 'SE', 'CH', 'TR', 'GB']

      # Wirecard supports all major credit and debit cards:
      # Visa, Mastercard, American Express, Diners Club,
      # JCB, Switch, VISA Carte Bancaire, Visa Electron and UATP cards.
      # They also support the latest anti-fraud systems such as Verified by Visa or Master Secure Code.
      self.supported_cardtypes = [
        :visa, :master, :american_express, :diners_club, :jcb, :switch
      ]

      # The homepage URL of the gateway
      self.homepage_url = 'http://www.wirecard.com'

      # The name of the gateway
      self.display_name = 'Wirecard'

      # The currency should normally be EUROs
      self.default_currency = 'EUR'

      # 100 is 1.00 Euro
      self.money_format = :cents

      def initialize(options = {})
        # verify that username and password are supplied
        requires!(options, :login, :password)
        # unfortunately Wirecard also requires a BusinessCaseSignature in the XML request
        requires!(options, :signature)
        @options = options.dup
        super
      end

      # Should run against the test servers or not?
      def test?
        @options[:test] || super
      end
      
      # WireCard supports storing of credit card information on their servers. To do this, set the
      # :recurring => "Initial" option in your first transaction and the :signature option to 56501 (batch booking 
      # at acquirer Wirecard Bank).
      # To use a saved credit card, set the :recurring => "Repeated" option and supply the authorization
      # of the original transaction.
      # If a repeated transaction doesn't contain the amount of money, the original amount of the first
      # transaction is used. You can authorize, capture or purchase a different amount by simply
      # supplying a different amount to the method call.
      
      # Preauthorization
      def preauthorize(money, creditcard_or_recurring_authorization, options = {})
        prepare_options_hash(options, creditcard_or_recurring_authorization)
        request = build_request(:preauthorization, money, @options)
        commit(request)
      end

      # Authorization
      def authorize(money, creditcard_or_recurring_authorization, options = {})
        prepare_options_hash(options, creditcard_or_recurring_authorization)
        request = build_request(:authorization, money, @options)
        commit(request)
      end


      # Capture Authorization
      def capture(money, authorization, options = {})
        options[:authorization] = authorization
        prepare_options_hash(options)
        request = build_request(:capture_authorization, money, @options)
        commit(request)
      end


      # Purchase
      def purchase(money, creditcard_or_recurring_authorization, options = {})
        prepare_options_hash(options, creditcard_or_recurring_authorization)
        request = build_request(:purchase, money, @options)
        commit(request)
      end

      # TODO: What is the equivalent wirecard transaction type?
      # def void(identification, options = {})
      # end
      
      # TODO: What is the equivalent wirecard transaction type?
      # def credit(money, identification, options = {})
      # end
      
    private

      def prepare_options_hash(options, creditcard_or_recurring_authorization = nil)
        if creditcard_or_recurring_authorization.is_a?(String)
          options[:authorization] = creditcard_or_recurring_authorization
        elsif creditcard_or_recurring_authorization.is_a?(CreditCard)
          options[:credit_card] = creditcard_or_recurring_authorization
        end

        @options.update(options)
        setup_address_hash!(options)
      end

      # Create all address hash key value pairs so that
      # it still works if only provided with one or two of them
      def setup_address_hash!(options)
        options[:billing_address] = options[:billing_address] || options[:address] || {}
        options[:shipping_address] = options[:shipping_address] || {}
        # Include Email in address-hash from options-hash
        options[:billing_address][:email] = options[:email] if options[:email]
      end

      # Contact WireCard, make the XML request, and parse the
      # reply into a Response object
      def commit(request)
        if raw_xml_debug_output
          puts "+++RAW OUTGOING XML+++"
          puts request
          puts "+++RAW OUTGOING XML+++"
        end
	      headers = { 'Content-Type' => 'text/xml',
	                  'Authorization' => encoded_credentials }

	      response = parse(ssl_post(test? ? TEST_URL : LIVE_URL, request, headers))
        # Pending Status also means Acknowledged (as stated in their specification)
	      success = response[:FunctionResult] == "ACK" || response[:FunctionResult] == "PENDING"
	      message = response[:Message]
        authorization = (success && TRANSACTIONS_WITH_AUTHORIZATION_RESPONSE.include?(@options[:action])) ? response[:GuWID] : nil

        Response.new(success, message, response,
          :test => test?,
          :authorization => authorization,
          :avs_result => { :code => response[:avsCode] },
          :cvv_result => response[:cvCode]
        )
      end

      # Generates the complete xml-message, that gets sent to the gateway
      def build_request(action, money, options = {})
				xml = Builder::XmlMarkup.new :indent => 2
				xml.instruct!
				xml.tag! 'WIRECARD_BXML' do
				  xml.tag! 'W_REQUEST' do
          xml.tag! 'W_JOB' do
              # Merchants can store a unique token for this job inside the JobID tag. As we already put the :order_id into
              # the TransactionID tag, leave this empty. WireCard docs state, that this field can be empty, but must be present.
              xml.tag! 'JobID', ''
              # UserID for this transaction
              xml.tag! 'BusinessCaseSignature', options[:signature] || options[:login]
              # Create the whole rest of the message
              add_transaction_data(xml, action, money, options)
				    end
				  end
				end
				xml.target!
      end

      # Includes the whole transaction data (payment, creditcard, address)
      def add_transaction_data(xml, action, money, options = {})
        options[:action] = action
        # TODO: require order_id instead of auto-generating it if not supplied
        options[:order_id] ||= generate_unique_id
        transaction_type = action.to_s.upcase

        xml.tag! "FNC_CC_#{transaction_type}" do
          # Merchants can store a unique token for this function inside the FunctionID tag. As we already put the :order_id into
          # the TransactionID tag, leave this empty. WireCard docs state, that this field can be empty, but must be present.
          xml.tag! 'FunctionID', ''

          xml.tag! 'CC_TRANSACTION' do
            xml.tag! 'TransactionID', options[:order_id]
            xml.tag! 'Usage', options[:description] # To be able to use this field it has to be ordered separately. Max length is 13 characters for VISA and Mastercard.
            if TRANSACTIONS_WITH_AUTHORIZATION_RESPONSE.include?(action)
              add_invoice(xml, money, options)
              add_creditcard(xml, options[:credit_card])
              add_address(xml, options[:billing_address])
            end
            add_recurring_info(xml, options)
            add_customer_data(xml, options)
          end
        end
      end

      def add_recurring_info(xml, options)
        xml.tag! 'GuWID', options[:authorization] if options[:authorization]
        xml.tag! 'RECURRING_TRANSACTION' do
          xml.tag! 'Type', options[:recurring] || 'Single'
        end
      end
      
			# Includes the payment (amount, currency, country) to the transaction-xml
      def add_invoice(xml, money, options)
        xml.tag!('Amount', amount(money)) if money
        xml.tag!('Currency', options[:currency] || currency(money)) if money
        xml.tag!('CountryCode', options[:billing_address][:country]) if options[:billing_address]
      end

			# Includes the credit-card data to the transaction-xml
			def add_creditcard(xml, creditcard)
        return if creditcard.nil?
        xml.tag! 'CREDIT_CARD_DATA' do
          xml.tag! 'CreditCardNumber', creditcard.number
          xml.tag! 'CVC2', creditcard.verification_value
          xml.tag! 'ExpirationYear', creditcard.year
          xml.tag! 'ExpirationMonth', format(creditcard.month, :two_digits)
          xml.tag! 'CardHolderName', [creditcard.first_name, creditcard.last_name].join(' ')
        end
      end

			# Includes the IP address of the customer to the transaction-xml
      def add_customer_data(xml, options)
        return unless options[:ip]
				xml.tag! 'CONTACT_DATA' do
					xml.tag! 'IPAddress', options[:ip]
				end
			end

      # Includes the address to the transaction-xml
      def add_address(xml, address)
        return if address.nil?
        xml.tag! 'CORPTRUSTCENTER_DATA' do
	        xml.tag! 'ADDRESS' do
	          xml.tag! 'Address1', address[:address1]
	          xml.tag! 'Address2', address[:address2] if address[:address2]
	          xml.tag! 'City', address[:city]
	          xml.tag! 'ZipCode', address[:zip]
	          xml.tag! 'State', address[:state].blank? ? 'N/A' : address[:state]
	          xml.tag! 'Country', address[:country]
	          xml.tag! 'Phone', address[:phone]
	          xml.tag! 'Email', address[:email]
	        end
	      end
      end


      # Read the XML message from the gateway and check if it was successful,
			# and also extract required return values from the response.
      def parse(xml)
        if raw_xml_debug_output
          puts "+++RAW INCOMING XML+++"
          puts xml
          puts "+++RAW INCOMING XML+++"
        end
        basepath = '/WIRECARD_BXML/W_RESPONSE'
        response = {}

        xml = REXML::Document.new(xml)
        if root = REXML::XPath.first(xml, "#{basepath}/W_JOB")
          parse_response(response, root)
        elsif root = REXML::XPath.first(xml, "//ERROR")
          parse_error(response, root)
        else
          response[:Message] = "No valid XML response message received. \
                                Propably wrong credentials supplied with HTTP header."
        end

        response
      end

      # Parse the <ProcessingStatus> Element which containts all important information
      def parse_response(response, root)
        status = nil
        # get the root element for this Transaction
        root.elements.to_a.each do |node|
          if node.name =~ /FNC_CC_/
            status = REXML::XPath.first(node, "CC_TRANSACTION/PROCESSING_STATUS")
          end
        end
        message = ""
        if status
          if info = status.elements['Info']
            message << info.text
          end
          # Get basic response information
          status.elements.to_a.each do |node|
            response[node.name.to_sym] = (node.text || '').strip
          end
        end
        parse_error(root, message)
        response[:Message] = message
      end

      # Parse a generic error response from the gateway
      def parse_error(root, message = "")
        # Get errors if available and append them to the message
        errors = errors_to_string(root)
        unless errors.strip.blank?
          message << ' - ' unless message.strip.blank?
          message << errors
        end
        message
      end

      # Parses all <ERROR> elements in the response and converts the information
      # to a single string
      def errors_to_string(root)
        # Get context error messages (can be 0..*)
        errors = []
        REXML::XPath.each(root, "//ERROR") do |error_elem|
          error = {}
          error[:Advice] = []
          error[:Message] = error_elem.elements['Message'].text
          error_elem.elements.each('Advice') do |advice|
            error[:Advice] << advice.text
          end
          errors << error
        end
        # Convert all messages to a single string
        string = ''
        errors.each do |error|
          string << error[:Message]
          error[:Advice].each_with_index do |advice, index|
            string << ' (' if index == 0
            string << "#{index+1}. #{advice}"
            string << ' and ' if index < error[:Advice].size - 1
            string << ')' if index == error[:Advice].size - 1
          end
        end
        string
      end

      # Encode login and password in Base64 to supply as HTTP header
      # (for http basic authentication)
      def encoded_credentials
        credentials = [@options[:login], @options[:password]].join(':')
        "Basic " << Base64.encode64(credentials).strip
      end
      
    end
  end
end

