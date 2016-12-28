#
#
#

require 'base/sessions/shell_extensions'
require 'base/sessions/cache'
require 'base/sessions/updatedb'

module Msf
  module Sessions
    #
    # Offline Session for testing and "offline" analyses of downloaded output
    # (files and command output)
    #
    class Offline < CommandShell
      include Msf::Session::Basic
      include Msf::Session::Provider::SingleCommandShell
      include Msf::Post::Common
      include Msf::Sessions::SessionCaching
      include Msf::Sessions::Updatedb

      attr_accessor :arch
      attr_accessor :platform
      attr_accessor :verbose
      # attr_accessor :data_dir

      def initialize(*args)
        self.verbose = false
        @datadir = nil
        @offline = nil
        # self.staekka = true
        self.platform = "unix" # XXX: todo
        super
      end

      #
      # just a description
      #
      def desc
        "Offline analyse"
      end

      def type
        "offline shell"
      end

      def inspect
        "#<Session:#{type}  " # Fixes highlighting
      end

      def exec_cmd(command, _arguments = nil, _opts = nil)
        # $stdout.puts "exec_cmd(#{command})"
        offline_cmd(command)
      end

      def shell_command_token(cmd, _timeout = 10, _absolute_timeout = nil)
        # $stdout.puts "shell_command_token(#{cmd})"
        offline_cmd(cmd)
      end

      def offline_cmd(command)
        # $stdout.puts "offline_cmd(#{command})"

        if command.nil?
          #$stdout.puts "NIL(#{command})"
          return ''
        end

        command.chomp!
        command.strip!
        if command.empty?
          #$stdout.puts "EMPTY(#{command})"
          return ''
        end

        if command.start_with? '/'
          # $stdout.puts "Absolute cmd"
          cmd = ::File.basename command
        elsif command.start_with? './'
          # $stdout.puts "Relative cmd"
          cmd = ::File.basename command
        elsif command.match(" ")
          (cmd,) = command.split(" ")
        else
          cmd = command
        end

        if command.match(" ")
          cmd_options = command[(command.index(cmd) + cmd.length + 1) .. -1]
        else
          cmd_options = nil
        end


        @offline.exec(cmd, cmd_options)
      end

      def offline_init(type)
        @offline = OfflineDefault.new if type == "default"
        raise "Offline type not valid" if @offline.nil?
        @offline.path = @datadir
      end

      def offline_path(dir)
        @datadir = dir
      end

      def readable?(path)
        @offline.readable?(path)
      end

      def writeable?(path)
        @offline.writeable?(path)
      end

      def file?(file)
        @offline.file?(file)
      end

      def exists?(file)
        @offline.exists?(file)
      end

      def directory?(file)
        @offline.directory?(file)
      end

      def suid?(file)
        @offline.suid?(file)
      end

      def empty?(file)
        @offline.empty?(file)
      end

      def symlink?(file)
        @offline.symlink?(file)
      end

      def filesize(file)
        @offline.filesize(file)
      end

      def read_file(file)
        @offline.read_file(file)
      end

      def remove_colors(data)
        data.gsub(/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]/, "")
      end

      #
      # Default offline session handles command output and files stored on
      # "default" path
      #   files:
      #     path/file
      #   command output:
      #     path/output/command options .txt
      #
      class OfflineDefault
        attr_accessor :path
        def initialize
          @path = nil
        end

        def exec(cmd, options)
          # $stdout.puts("__Offline.exec(#{cmd} [#{options}] )")
          out = ''
          # $stdout.puts "___CMD_OUT: |#{@path}/output/#{cmd}#{options}.txt|"
          if ::File.exist? "#{@path}/output/#{cmd}#{options}.txt"
            out = ::File.read "#{@path}/output/#{cmd}#{options}.txt"
          elsif   ::File.exist? "#{@path}/output/#{cmd}.txt"
            out = ::File.read "#{@path}/output/#{cmd}.txt"
          end

          out
        end

        def read_file(file)
          out = ''
          file = "#{@path}/#{file}"
          # $stdout.puts "___FILE? |#{file}|"
          out = ::File.read(file) if ::File.exist? file
          out
        end

        def readable?(path)
          path = "#{@path}/#{path}"
          ::File.readable?(path)
        end

        def writeable?(path)
          path = "#{@path}/#{path}"
          ::File.writable?(path)
        end

        def file?(file)
          file = "#{@path}/#{file}"
          ::File.file?(file)
        end

        def exists?(file)
          file = "#{@path}/#{file}"
          ::File.exist?(file)
        end

        def directory?(file)
          file = "#{@path}/#{file}"
          ::File.directory?(file)
        end

        def suid?(file)
          file = "#{@path}/#{file}"
          ::File.setuid?(file)
        end

        def empty?(file)
          file = "#{@path}/#{file}"
          filesize(file).zero?
        end

        def symlink?(file)
          file = "#{@path}/#{file}"
          ::File.symlink?(file)
        end

        def filesize(file)
          file = "#{@path}/#{file}"
          if ::File.exist?(file)
            ::File.size(file)
          else
            0
          end
        end
      end
    end
  end
end

# module Msf::Post::File
#  def read_file(file_name)
#    $stdout.puts "read_file(#{file_name})"
#    ''
#  end
# end
