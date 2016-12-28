# Advanced Post Exploitation

# Metasploit
module Msf
  #
  # Staekka is an extension for metasploit implementing some missing features
  #
  module Staekka
    # empty for loading
  end
end



module Msf
  # This plugin manages)StaekkaShell integrated to Metasploit
  class Plugin::Staekka < Msf::Plugin
    include Msf::Staekka

    #
    # Called when an instance of the plugin is created.
    #
    def initialize(framework, opts)
      super
      @staekka_path = nil
      if opts['Path']
        @staekka_path = opts['Path'].to_s.strip
        unless ::File.directory?(@staekka_path)
          raise "Staekka directory not found"
        end
      else
        # check default path
        if ::File.directory? ENV['STAEKKA_PATH']
            @staekka_path = ENV['STAEKKA_PATH']
        else
          [ "#{ENV['HOME']}/.staekka", "/usr/local/staekka", "/opt/staekka"].each do |dir|
            if ::File.directory? dir
              @staekka_path = dir
              break
            end
          end
        end
      end
      if @staekka_path.nil?
        raise "Need Staekka path! (option Path or export STAEKKA_PATH=)"
      end

      # add path to Msf config
      path = @staekka_path
      Msf::Config.singleton_class.send(:define_method, :staekka_path) do
        path
      end

      $LOAD_PATH << @staekka_path + "/lib"
      if opts['Test'] == 'true'
        $LOAD_PATH << "test/lib"
        if opts['Testdir']
          testpath = opts['Testdir']
        elsif ::File.file? "#{ENV['STAEKKA_TEST']}/lib/modules_test_extra.rb"
          testpath = "#{ENV['STAEKKA_TEST']}/"
        elsif ::File.file? "#{@staekka_path}/test/lib/modules_test_extra.rb"
          testpath = "#{@staekka_path}/test"
        elsif ::File.file? "#{@staekka_path}-test/lib/modules_test_extra.rb"
          testpath = "#{@staekka_path}-test"
        else
          raise "Cannot find library path"
        end
        if ::File.directory? testpath
          $LOAD_PATH << testpath + "/lib"
          @staekka_test_path = testpath
        else
          raise "No directory #{testpath}"
        end
      end
      add_extra_gems_to_path
      require 'staekka'
      require 'base/sessions/pty'
      cmd_loadpath(@staekka_path + "/modules")
      # cmd_loadpath(STAEKKA_MODULES)
      # Msf::Ui::Console::CommandDispatcher.Core.cmd_loadpath(STAEKKA_MODULES)
      print_line("%red" + Staekka::Banner.to_s + "%clr\n\n")
      # load_modules_message = "Now you may load the modules. To load the default modules enter\n"
      # load_modules_message << "loadpath #{STAEKKA_MODULES}"
      # print_line(load_modules_message)
      set_documentation_path
    end

    #
    # setting search path for extra loaded documentation files
    # (loaded via info_path plugin)
    #
    def set_documentation_path
      if Msf::Config.methods.include? :doc_search_path
        my_path = File.expand_path(File.join(Msf::Config.staekka_path, 'documentation', 'modules' ))
        unless Msf::Config.doc_search_path.include? my_path
          Msf::Config.doc_search_path << my_path
        end
      end
    end

    #
    # unloading staekka documentaion from seach path
    #
    def unset_documentation_path
      if Msf::Config.methods.include? :doc_search_path
        my_path = File.expand_path(File.join(Msf::Config.staekka_path, 'documentation', 'modules' ))
        unless Msf::Config.doc_search_path.include? my_path
          Msf::Config.doc_search_path.delete my_path
        end
      end
    end

    #
    # searches for custom used gems and adds gems path to LOAD_PATH
    # (maybe this should be rewritten for using bundler...)
    #
    def add_extra_gems_to_path
      gems_to_load = []
      # parse Gemfile and search for gems to load
      gemfile = File.expand_path(File.join(Msf::Config.staekka_path, 'Gemfile'))
      ::File.read(gemfile).each_line do |line|
        line.gsub!(/^\s*#.*$/, '')
          if line.match(/gem\s*"(.*?)"/)
          gems_to_load << $1
        end
      end

      # search for matching files
      extra_libs = []
      gems_to_load.each do |lib|
        gem_path = Gem.path
        # for bundler git installations
        gem_path <<  Bundler.user_bundle_path.join(Bundler.ruby_scope).to_s
        # fix for Kali
        #gem_path +=  Dir.glob("/var/lib/gems/2.*").sort
        #
        gem_path.each do |d|
          tmp = Dir.glob(d + "/{gems/,}" +"{ruby-,}#{lib}-*/lib/") # added "ruby-" for fixing "ruby-termios" -> "termios"
          unless tmp.empty?
            # check if already loaded
            tmp.each do |l|
              if $LOAD_PATH.include? ::File.dirname(l)
                break
              end
            end
            # use newest version
            lib_path =  tmp.sort_by {|o| Gem::Version.new(o.match(/\/gems\/.*-(\w.*?)\//).to_a[1])}.last
            extra_libs << lib_path
            break
          end
        end
      end

      #
      extra_libs.each do |lib_path|
        unless $LOAD_PATH.include? lib_path
          $LOAD_PATH << lib_path
        end
      end
    end

    #
    # Removes the console menus created by the plugin
    #
    def cleanup
      unset_documentation_path
      Msf::Config.singleton_class.send(:remove_method, :staekka_path)
      #stop
      remove_console_dispatcher('staekka')
    end

    #
    # This method returns a short, friendly name for the plugin.
    #
    def name
      "staekka"
    end

    #
    # Returns description of the plugin (60 chars max)
    #
    def desc
      "Post exploitation addons for Linux/Unix systems"
    end

    #
    # Loads the extra modules
    #
    def cmd_loadpath(*args)
      # defanged?

      totals    = {}
      overall   = 0
      curr_path = nil

      begin
        # Walk the list of supplied search paths attempting to add each one
        # along the way
        args.each do |path|
          curr_path = path

          # Load modules, but do not consult the cache
          next unless (counts = framework.modules.add_module_path(path))
          counts.each_pair do |type, count|
            totals[type] = totals[type] ? (totals[type] + count) : count

            overall += count
          end
        end
      rescue NameError, RuntimeError
        log_error("Failed to add search path #{curr_path}: #{$ERROR_INFO}")
        return true
      end

      added = "Loaded #{overall} modules:\n"

      totals.each_pair do |type, count|
        added << "    #{count} #{type}#{count != 1 ? 's' : ''}\n"
      end

      print_line(added)
    end
  end
end
