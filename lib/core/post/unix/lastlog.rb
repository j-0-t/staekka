#
# Lastlog binary logs
#
class LastLog
  attr_accessor :lastlog
  attr_accessor	:entries
  attr_accessor	:uidmap

  class LastLogStruct < BinData::Record
    endian	:little
    uint32		:ll_time
    string		:ll_line, length: 32
    string		:ll_host, length: 256
  end

  def initialize
    @lastlog = LastLogStruct.new
    @entries = {}
    @uidmap = {}
    @fields = ['ll_time', 'll_line', 'll_host', 'll_user']
  end

  def size
    @lastlog.to_binary_s.length
  end

  def size_ok?(file)
    filesize = ::File.size(file)
    if (filesize % size).zero?
      true
    else
      false
    end
  end

  def int_to_time(int)
    if int.nil? || int.zero?
      "**Never logged in**"
    else
      Time.at(int).to_s
    end
  end

  def time_to_int(time)
    Time.parse(time).to_i
  end

  def read_uid(uid)
    lastlog.read(@entries[uid])
  end

  def dump_entry(uid)
    data =  read_uid(uid)
    out = {}
    out["ll_user"] = uid
    # out["ll_time"] = int_to_time(data.ll_time)	if data.respond_to? :ll_time
    out["ll_time"] = data.ll_time								if data.respond_to? :ll_time
    out["ll_line"] = data.ll_line								if data.respond_to? :ll_line
    out["ll_host"] = data.ll_host								if data.respond_to? :ll_host
    out
  end

  def create_entry(data, uid)
    # tmp = dump_entry(uid)
    new_lastlog = hash2data(data, uid)
    new_lastlog
  end

  def create_lastlog
    LastLogStruct.new
  end

  def hash2data(data, _uid)
    new_lastlog = create_lastlog
    new_lastlog.ll_time = data["ll_time"]
    new_lastlog.ll_line = data["ll_line"]
    new_lastlog.ll_host = data["ll_host"]
    new_lastlog
  end

  def read_passwd(data = "")
    data.to_s.split("\n").each do |line|
      tmp = line.split(":")
      @uidmap[tmp[2].to_i] = tmp[0]
    end
  end

  def uid_to_username(uid)
    # if @uidmap.empty?
    #	 read_passwd()
    # end
    user = @uidmap[uid]
    if user.nil?
      "uid=#{uid}"
    else
      user
    end
  end

  def print_entry(uid)
    out = ''
    tmp = dump_entry(uid)
    ll_time =	 int_to_time(tmp['ll_time'])
    ll_user =  uid_to_username(tmp['ll_user'])
    ll_line =  tmp['ll_line'].delete "\x00"
    ll_host =  tmp['ll_host'].delete "\x00"
    out << sprintf("%-16s %-10s %-16s %-26s", ll_user, ll_line, ll_host, ll_time)
    out << "\n"
    out
  end

  def read_file(io)
    io.rewind
    i = 0
    until io.eof?
      data = @lastlog.read(io)
      @entries[i] = data.to_binary_s
      i += 1
    end
    i = 0
  end

  def each_entry(io)
    read_file(io) if @entries.empty?
    @entries.each_key do |uid|
      yield(self, uid)
    end
  end
end
