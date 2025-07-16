import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
from urllib.parse import urlparse
import time, urllib.request, re, http.client
import threading

# Global variable for the output file
output_file_name = 'com_user.txt'
file2 = None # Will be opened when the scan starts

def check(site, output_text_widget):
    """
    Checks a given site for the 'Image Manager' string and writes the URL to a file if found.
    """
    try:
        with urllib.request.urlopen(site, timeout=10) as response:
            w = response.read().decode('utf-8', errors='ignore')
        
        if re.findall('Image Manager', w):
            ox = urlparse(site)
            message = f'w00t ! ! Found In  => {ox.netloc}\n'
            output_text_widget.insert(tk.END, message)
            output_text_widget.see(tk.END) # Scroll to the end
            if file2:
                file2.write(ox.netloc + '\n')
                file2.flush() # Ensure data is written immediately
    except (urllib.error.URLError, socket.error, http.client.HTTPException, IOError) as err:
        # Pass silently as in the original code, but log to console for debugging if needed
        # print(f"Error checking {site}: {err}")
        pass
    except Exception as e:
        # Catch any other unexpected errors
        # print(f"An unexpected error occurred for {site}: {e}")
        pass

def xlol(site, output_text_widget):
    """
    Attempts to open a URL and then calls check() if successful.
    """
    try:
        with urllib.request.urlopen(site, timeout=10) as response:
            pass # Just try to open it
        check(site, output_text_widget)
    except (urllib.error.URLError, socket.error, http.client.HTTPException, IOError) as err:
        # Pass silently as in the original code
        pass
    except Exception as e:
        # Catch any other unexpected errors
        pass

def bing_it(ip, output_text_widget, start_button):
    """
    Performs a Bing search for the given IP and checks the found URLs.
    """
    global file2
    try:
        file2 = open(output_file_name, 'a')
        output_text_widget.insert(tk.END, f"Scanning started for IP: {ip}\n")
        output_text_widget.see(tk.END)

        page = 0
        while page <= 200:
            try:
                bing_url = f"http://www.bing.com/search?q={ip}+index.php?option=com_&first={page}"
                output_text_widget.insert(tk.END, f"Searching Bing: {bing_url}\n")
                output_text_widget.see(tk.END)

                with urllib.request.urlopen(bing_url, timeout=15) as openbing:
                    readbing = openbing.read().decode('utf-8', errors='ignore')
                
                findbing = re.findall('<div class="sb_tlst"><h3><a href="(.*?)" h=', readbing)

                for x in findbing:
                    o = urlparse(x)
                    # Ensure the URL is valid before proceeding
                    if o.netloc:
                        y = o.path.replace('/index.php', '')
                        message = f'checking {o.netloc}\n'
                        output_text_widget.insert(tk.END, message)
                        output_text_widget.see(tk.END)
                        
                        target_url = f'http://{o.netloc}{y}/index.php?option=com_users&view=registration'
                        check(target_url, output_text_widget)
                
                page += 10
            except (http.client.IncompleteRead, urllib.error.URLError, socket.error, http.client.HTTPException, IOError) as err:
                # Pass silently as in the original code
                # print(f"Error during Bing search or URL check: {err}")
                pass
            except Exception as e:
                # Catch any other unexpected errors during the loop
                # print(f"An unexpected error occurred during Bing search loop: {e}")
                pass
            
            # Small delay to avoid overwhelming the server and for better UI responsiveness
            time.sleep(0.5) 

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during the scan: {e}")
    finally:
        if file2:
            file2.close()
            file2 = None
        output_text_widget.insert(tk.END, "Scan finished.\n")
        output_text_widget.see(tk.END)
        start_button.config(state=tk.NORMAL) # Re-enable the start button


def start_scan(ip_entry, output_text_widget, start_button):
    """
    Starts the scanning process in a separate thread to keep the GUI responsive.
    """
    ip = ip_entry.get().strip()
    if not ip:
        messagebox.showwarning("Input Error", "Please enter a Domain/IP.")
        return

    start_button.config(state=tk.DISABLED) # Disable button during scan
    output_text_widget.delete(1.0, tk.END) # Clear previous output
    output_text_widget.insert(tk.END, "Initializing scan...\n")
    output_text_widget.see(tk.END)

    # Start the scan in a new thread
    scan_thread = threading.Thread(target=bing_it, args=(ip, output_text_widget, start_button))
    scan_thread.daemon = True # Allow the thread to exit with the main program
    scan_thread.start()

def create_gui():
    """
    Creates the main GUI window and widgets.
    """
    root = tk.Tk()
    root.title("com_user Server Scanner")
    root.geometry("800x600")
    root.resizable(True, True) # Allow resizing

    # Main frame for layout
    main_frame = tk.Frame(root, padx=10, pady=10)
    main_frame.pack(fill=tk.BOTH, expand=True)

    # Title Label
    title_label = tk.Label(main_frame, text="com_user Server Scanner", font=("Arial", 16, "bold"), fg="#0056b3")
    title_label.pack(pady=10)

    # Author Label
    author_label = tk.Label(main_frame, text="Coded by khedr0x00", font=("Arial", 10, "italic"))
    author_label.pack(pady=5)

    # Input Frame
    input_frame = tk.Frame(main_frame)
    input_frame.pack(pady=10)

    domain_label = tk.Label(input_frame, text="Domain/IP:", font=("Arial", 12))
    domain_label.pack(side=tk.LEFT, padx=5)

    ip_entry = tk.Entry(input_frame, width=40, font=("Arial", 12), bd=2, relief=tk.GROOVE)
    ip_entry.pack(side=tk.LEFT, padx=5)

    start_button = tk.Button(input_frame, text="Start Scan", 
                             command=lambda: start_scan(ip_entry, output_text, start_button),
                             font=("Arial", 12, "bold"), bg="#4CAF50", fg="white",
                             activebackground="#45a049", activeforeground="white",
                             relief=tk.RAISED, bd=3)
    start_button.pack(side=tk.LEFT, padx=10)

    # Output Text Area
    output_text = scrolledtext.ScrolledText(main_frame, width=80, height=25, font=("Consolas", 10), 
                                            wrap=tk.WORD, bg="#f0f0f0", fg="#333", bd=2, relief=tk.SUNKEN)
    output_text.pack(pady=10, fill=tk.BOTH, expand=True)

    # Bind the close event to a function to ensure file is closed
    root.protocol("WM_DELETE_WINDOW", lambda: on_closing(root))

    root.mainloop()

def on_closing(root):
    """
    Handles the window closing event to ensure the output file is closed.
    """
    global file2
    if file2:
        file2.close()
        file2 = None
    root.destroy()

if __name__ == "__main__":
    create_gui()
