import sys
import subprocess
import threading

class Iperf():
    """
    Install and start a server automatically
    """
    try:
        if not nextline:
            mtu = None
    except NameError:
        mtu = None
    # The following is a mess - since I'm installing iperf3 in the function
    # Surely there is another easier way to get this into the charm?
    def __init__(self):
      #try:
      #  subprocess.check_call(['pgrep', 'iperf'], stderr=subprocess.STDOUT)
      #      if a:
      thread = threading.Thread(target=self.start_server, args=())
      thread.start()
      #except:
      #  pass
            #hookenv.log(sys.exc_info()[0], 'INFO')

    def start_server(self):
      process = subprocess.Popen(['iperf', '-s', '-m'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
      while True:
          nextline = process.stdout.readline()
          nextline = nextline.decode("utf-8")
          if nextline == '' and process.poll() is not None:
              break
          if "bits" in nextline:
              self.speed = nextline.rsplit(' ', 2)[1] 
              sys.stdout.write(self.speed)
              sys.stdout.write("\n")
          if "MTU" in nextline:
              self.mtu = nextline.rsplit(' ', 4)[1]
              sys.stdout.write(self.mtu)
          sys.stdout.flush()
          #output = process.communicate()[0]
          #exitCode = process.returncode
          #  
          #output = exitCode
   
          #if (exitCode == 0):
          #    pass
          #elif exitCode:
          #    raise Exception(command, exitCode, output)


perf = Iperf()
#print (perf.mtu)
