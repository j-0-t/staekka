module Msf
	module Staekka
		def staekka_path
			#File.realpath (File.dirname(__FILE__) + '/../../')
			File.realpath @staekka_path
		end
	end
end
