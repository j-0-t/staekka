#
#
require 'msf/core'
require 'core/post/staekka'

class MetasploitModule < Msf::Post
  include Msf::Staekka
  include Msf::Post::Staekka

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Updatedb',
                      'Description'   => %q(Creating a updatedb for faster file searches),
                      'Author'        => [ 'jot'],
                      'SessionTypes'  => [ 'shell' ]))
    register_options(
      [
        OptPath.new('UPDATEDB_FILE', [ false, 'Path to a local pre-created updatedb file (created with "find")']),
        OptBool.new('TESTMODE', [ false, 'Load a pre-defined test database (for testing)', true]), # XXX
        OptString.new('FIND',  [ false, 'A string to search for files (regex is ok)' ]),
        OptBool.new('SUID',  [ false, 'Find all SUID files']),
        OptBool.new('WORLD_WRITEABLE', [ false, 'Find all world writeable files']),
        OptString.new('PERMS', [ false, 'Find all files with special permissions']),
        OptString.new('LS', [ false, 'cached "ls -l" of a file ']),
        OptString.new('CACHE', [ false, 'a token to cache the results of the search']),
        OptString.new('READ_CACHE', [ false, 'a token to read cached results'])
      ], self.class
    )
  end

  def run
    rootdir = '/'
    updatedb_file = nil
    staekka_path  = ENV['STAEKKA_TEST']
    if datastore['TESTMODE'] == true
      updatedb_file = staekka_path + "/data/files/updatedb-2"
      unless ::File.file? updatedb_file
        raise "Testfile does not exists '#{updatedb_file}' Maybe you have to set staekka env (export STAEKKA_TEST=...)"
      end
    end
    updatedb_file = datastore['UPDATEDB_FILE'] if datastore['UPDATEDB_FILE']
    unless session.locate_updatedb? && updatedb_file.nil?
      # already loaded
      session.locate_updatedb(rootdir, updatedb_file)
    end

    if datastore['FIND']
      search = datastore['FIND']
      out = session.updatedb_search(search)
      add_cache out
      print_status("Found files for #{search}:")
      out.each do |file|
        print_status file
      end
    end
    if datastore['SUID'] == true
      out = session.updatedb_search_suid
      add_cache out
      print_status("Suid files:")
      out.each do |file|
        print_status file
      end
    end
    if datastore['WORLD_WRITEABLE'] == true
      out = session.updatedb_search_world_writeable
      add_cache out
      print_status("World writeable files:")
      out.each do |file|
        print_status file
      end
    end
    # TODO: octal permissions
    if datastore['PERMS']
      perms = datastore['PERMS']
      unless perms.to_i.zero?
        raise "Octal permission are currently not implemented"
      end
      out = session.updatedb_search_permissions(perms)
      add_cache out
      out.each do |file|
        print_status file
      end
    end
    if datastore['LS']
      file = datastore['LS']
      out = session.updatedb_file_ls(file)
      add_cache out
      print_status("ls -l #{file}\n#{out}")
    end
    if datastore['READ_CACHE']
      token = datastore['READ_CACHE']
      if session.methods.include? :cache
        if session.cache.exists?(token)
          data = session.cache.read(token)
          if data.class.to_s == 'String'
            print_status("Cached->#{token}:\n" + data)
          elsif data.class.to_s == 'Array'
            print_status("Cached->#{token}:")
            data.each do |line|
              print_status line.to_s
            end
          else
            print_status("Cached->#{token}:\n#{data}")
          end
        end
      end
    end
  end

  def add_cache(data)
    if datastore['CACHE']
      token = datastore['CACHE']
      return nil unless session.methods.include? :cache
      if session.cache.exists?(token)
        tmp = session.cache.read(token)
        tmp << data
        session.cache.add(token, tmp)
      else
        session.cache.add(token, data)
      end

    end
  end
end
