
#
# Extending get_module_document() for searching inside of more than one
# directory for documentation templates
#
module Msf::Util::DocumentGenerator
      def self.get_module_document(mod)
        md = ''
        kb = ''
        Msf::Config.doc_search_path.each do |p|
          kb_path = File.join(p, "#{mod.fullname}.md")
          if File.exist?(kb_path)
            File.open(kb_path, 'rb') { |f| kb = f.read }
            break
          end
        end

        begin
          pr_finder = PullRequestFinder.new
          pr = pr_finder.search(mod)
        rescue PullRequestFinder::Exception => e
          pr = e
        end

        n = DocumentNormalizer.new
          items = {
            mod_description:   mod.description,
            mod_authors:       mod.send(:module_info)['Author'],
            mod_fullname:      mod.fullname,
            mod_name:          mod.name,
            mod_pull_requests: pr,
            mod_refs:          mod.references,
            mod_rank:          mod.rank,
            mod_platforms:     mod.send(:module_info)['Platform'],
            mod_options:       mod.options,
            mod_demo:          mod
        }

        if mod.respond_to?(:targets) && mod.targets
          items[:mod_targets] = mod.targets
        end

        n.get_md_content(items, kb)
      end


end


module Msf
  class Plugin::InfoPath < Msf::Plugin
     def initialize(framework, opts)
      super
      path = []
      if opts['Path']
        tmp = opts['Path'].to_s.strip.split(":")
        tmp.each do |d|
          if ::File.directory?(d)
            path << d
          else
            print_error "#{d} is not a directory and will be ignored"
          end
        end
      end

      documentation_path(path)
     end

      #
    # Extending the documentation template search path to:
    # 1: default path inside the default installation
    # 2: custom modules/documention inside the home directory (~/.msf4/documention/)
    # 3: documentation inside the staekka directory
    #
    def documentation_path(extra_path=[])
      path = [File.expand_path(File.join(Msf::Config.module_directory, '..', 'documentation', 'modules' )),
              File.expand_path(File.join(Msf::Config.user_module_directory, '..', 'documentation', 'modules' )),
      ]
      #if Msf::Config.method_defined? :staekka_path
      if Msf::Config.methods.include? :staekka_path
        path << File.expand_path(File.join(Msf::Config.staekka_path, 'documentation', 'modules' ))
      end
      path.concat(extra_path)

      Msf::Config.singleton_class.send(:define_method, :doc_search_path=) do |opt|
        @info_path = opt
        @info_path
      end
      Msf::Config.singleton_class.send(:define_method, :doc_search_path) do
        @info_path
      end
      Msf::Config.doc_search_path=path
    end

    def name
      "Info search path"
    end

    def desc
      "Extends search path for module documentation (info -d)"
    end

    def cleanup
      path=[File.expand_path(File.join(Msf::Config.module_directory, '..', 'documentation', 'modules' ))]
      Msf::Config.doc_search_path=path
      #stop
      remove_console_dispatcher('info_path')
    end


  end
end
