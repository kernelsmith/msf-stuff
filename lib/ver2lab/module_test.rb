module Outer
	module Middle
		def testmemiddle(str)
			puts "testmemiddle #{str}"
		end
		def testme(str)
			puts "middle testme: #{str}"
		end
		module Inner
			def testme(str)
				puts "inner testme: #{str}"
			end
		end
		module Inner2
			def testme(str)
				puts "inner2 testme: #{str}"
			end
		end
	end
end



