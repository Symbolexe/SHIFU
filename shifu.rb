require 'json'
require 'net/http'

# Colorize methods
def red(text); "\e[31m#{text}\e[0m" end
def green(text); "\e[32m#{text}\e[0m" end

def print_banner
  puts <<~BANNER
    ┌────────────────────────────────────────────┐
    │                  SHIFU                     │
    │           CVE Finder Toolkit               │
    └────────────────────────────────────────────┘
  BANNER
end

def search_by_cve_id(cve_id, output_file = nil)
  url = URI("https://access.redhat.com/labs/securitydataapi/cve.json?ids=#{cve_id}")

  begin
    response = Net::HTTP.get_response(url)

    case response.code
    when "200"
      begin
        cve_info = JSON.parse(response.body)[0]
        if cve_info.nil?
          puts red("Error: No CVE information found for #{cve_id}.")
        else
          display_cve_info(cve_info)
          save_to_file(cve_info, output_file) if output_file
        end
      rescue JSON::ParserError
        puts red("Error: Failed to parse JSON response.")
      end
    when "404"
      puts "CVE '#{cve_id}' does not exist."
    else
      puts red("Error: Failed to retrieve CVE information. HTTP status code: #{response.code}")
    end
  rescue StandardError => e
    puts red("Error: #{e.message}")
  end
end

def display_cve_info(cve_info)
  puts "CVE Information:"
  cve_info.each do |key, value|
    puts "#{key.capitalize.gsub('_', ' ')}: #{value}"
  end
end

def save_to_file(cve_info, output_file)
  File.open(output_file, 'a') do |file|
    file.puts "CVE Information:"
    cve_info.each do |key, value|
      file.puts "#{key.capitalize.gsub('_', ' ')}: #{value}"
    end
    file.puts
  end
  puts green("CVE Information has been saved to #{output_file}")
end

def valid_cve_ids?(cve_ids)
  cve_ids.split(",").all? { |cve_id| cve_id.match?(/^CVE-\d{4}-\d{4,}$/) }
end

def get_user_input(prompt)
  print prompt
  gets.chomp.strip
end

def process_cve_file(file_name)
  if File.exist?(file_name)
    File.foreach(file_name) do |line|
      search_by_cve_id(line.strip, 'result-cves.txt') unless line.strip.empty?
    end
  else
    puts red("Error: File '#{file_name}' not found.")
  end
end

def run
  print_banner
  loop do
    print "Do you want to enter CVE IDs manually or provide a file? (manual/file): "
    input_method = gets.chomp.downcase
    case input_method
    when 'manual'
      cve_ids = get_user_input("Enter CVE IDs separated by commas (e.g., CVE-2024-3096,CVE-2022-1234): ")
      if cve_ids.empty?
        puts "No CVE IDs provided."
        break
      elsif valid_cve_ids?(cve_ids)
        cve_ids.split(",").each do |cve_id|
          search_by_cve_id(cve_id.strip, 'result-cves.txt')
        end
      else
        puts red("Error: Invalid CVE ID format. Please provide valid CVE IDs separated by commas.")
      end
    when 'file'
      file_name = get_user_input("Enter the name of the file containing CVE IDs: ")
      process_cve_file(file_name)
    else
      puts red("Error: Invalid input method. Please choose 'manual' or 'file'.")
    end

    print "Do you want to perform another search? (y/n): "
    answer = gets.chomp.downcase
    break unless answer.start_with?('y')
  end

  puts "Thanks for using SHIFU!"
end

if $PROGRAM_NAME == __FILE__
  run
end
