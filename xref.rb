require 'set'
require 'erb'
require 'fileutils'
#--------------Parse Dwarfdump output-------------------------
system("llvm-dwarfdump --debug-line > dwarfdump.txt")
dwarfdump_file = File.open("dwarfdump.txt")
dwarfdump_lines = dwarfdump_file.readlines.map(&:chomp)
time = Time.now.getutc
files = Hash.new
line_table = Hash.new
relevant_files = Set.new
#define all my regexp needed for parsing dwarfdump output 
FILE_NUMBER = /file_names\[\s*(\d+)\]/
FILE_NAME = /name:\s"(.*)"/
TABLE_START = /Address            Line   Column File   ISA Discriminator Flags/
TABLE_LINE = /------------------ ------ ------ ------ --- ------------- -------------/
TABLE_ENTRY = /0x0*([1-9][0-9a-f]*)\s*(\d+)\s*\d+\s*(\d+).*/
table_found = false
len = dwarfdump_lines.length - 1
for i in 0..len
    #if current line is a file def, capture file index(m[1]) and look into next line to find file name(n[1])
    #and store in files hash with key = index, value = name
    m = dwarfdump_lines[i].match(FILE_NUMBER)
    if m != nil 
        n = dwarfdump_lines[i+1].match(FILE_NAME)
        files.store(m[1],n[1])
    end
    #if current file is the table start, we know we can start parsing table
    if dwarfdump_lines[i].match(TABLE_START)
        table_found = true
    end
    #if we have encountered the table:
    #capture the relevant address(entry[1]), the line number(entry[2]) and the file number(entry[3])
    #store values in line_table hash with key = address, value = array containing [line num, file number]
    #also, add file num into relevant_files set so we know which source files to load
    if table_found == true 
        if dwarfdump_lines[i].match(TABLE_LINE)
            next
        end
        entry = dwarfdump_lines[i].match(TABLE_ENTRY)
        if entry != nil
            line_and_file = [entry[2], entry[3]]
            line_table.store(entry[1], line_and_file)
            relevant_files.add(entry[3])
        end
    end
end
#uncomment the below if you want to see the output format of these hashes
#puts line_table
#puts files
dwarfdump_file.close

#--------------Load relevant C source files-------------------------
sources = Hash.new
relevant_files.each do |file_num|
    name = files.fetch(file_num)
    src_file = File.open(name)
    src_lines = src_file.readlines.map(&:chomp)
    sources.store(file_num, src_lines)
end
#puts sources

#--------------Parse Objdump output-------------------------
system("objdump -d > objdump.txt")
objdump_file = File.open("objdump.txt")
objdump_lines = objdump_file.readlines.map(&:chomp)
ADDRESS_FORMAT = /\s+([1-9][0-9a-f]*).*/
blocks = []
current_block_index = 0
start_new_block = true

#for reference: this is the format of line_table {"401126"=>["3", "1"], "40112a"=>["5", "1"], "401139"=>["6", "1"], "40113e"=>["7", "1"], "401140"=>["7", "1"]}

obj_len = objdump_lines.length - 1
for i in 0..obj_len
    line_num = i+1 #+1 because files start at line 1 not line 0
    if start_new_block == true
        #if at start of new block, initialize c_lines and assembly_lines which correspond to each other
        #populate c_lines by looking at the current line's address. Feth the line_and_file info stored
        #in the line_table hash for that address, and find the appropriate source line by using the file_num
        #as key in the sources hash to retrieve the source lines. index using src_line_num to retrieve line
        c_lines = []
        files_name = ""
        if current_block_index != 0
            match_addr = objdump_lines[i].match(ADDRESS_FORMAT)
            addr = match_addr[1]
            line_and_file = line_table.fetch(addr)
            src_line_num = line_and_file[0].to_i
            file_num = line_and_file[1]
            file_name = files.fetch(file_num)
            src_file = sources.fetch(file_num)
            line = src_file[src_line_num-1]
            c_lines << src_line_num.to_s + ". " + line
        end
        #add current line of assembly to assembly_lines for the new block
        assembly_lines = []
        assembly_lines << line_num.to_s + ". " + objdump_lines[i]
        current_block = [c_lines, assembly_lines, file_name]
        blocks << current_block #add new block to array of blocks
        start_new_block = false
        next
    end

    #if not  starting a new block, add current line of assembly to assembly_lines for the current block
    #and then check if the next line of assembly requires the start of a new block
    if start_new_block == false
        current_block = blocks[current_block_index]
        assembly_lines = current_block[1]
        assembly_lines << line_num.to_s + ". " + objdump_lines[i]

        if i != obj_len
            match_addr = objdump_lines[i+1].match(ADDRESS_FORMAT) #checks if next line should be start of new block
            if match_addr != nil
                addr = match_addr[1]
                if line_table.has_key?(addr)
                    start_new_block = true
                    current_block_index += 1
                end
            end
        end 
    end
end
#uncomment to see output of blocks array. 
#puts blocks.inspect

# render template
template = File.read('./template.html.erb')
result = ERB.new(template).result(binding)

index_template = File.read('./index_template.html.erb')
index_result = ERB.new(index_template).result(binding)

if File.exist?("HTML/index.html")
   File.delete("HTML/index.html")
end

File.new("HTML/index.html", "w")

# write result to file
File.open('HTML/index.html', 'w+') do |f|
  f.write index_result
end

if File.exist?("HTML/xref.html")
   File.delete("HTML/xref.html")
end

File.new("HTML/xref.html", "w")
# write result to file
File.open('HTML/xref.html', 'w+') do |f|
  f.write result
end

