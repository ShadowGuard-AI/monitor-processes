import argparse
import logging
import psutil
import time
import signal
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the command line argument parser.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Monitor system processes for suspicious activity.")
    parser.add_argument('--interval', type=int, default=60, help='Interval in seconds to check processes.')
    parser.add_argument('--cpu_threshold', type=float, default=90.0, help='CPU usage threshold percentage.')
    parser.add_argument('--mem_threshold', type=float, default=90.0, help='Memory usage threshold percentage.')
    parser.add_argument('--process_name', type=str, default=None, help='Monitor only specified process by name.')
    parser.add_argument('--log_file', type=str, default='process_monitor.log', help='Path to the log file.')
    return parser


def validate_args(args):
    """
    Validates the command line arguments.

    Args:
        args (argparse.Namespace): Parsed command line arguments.

    Returns:
        bool: True if arguments are valid, False otherwise.
    """
    if args.interval <= 0:
         logging.error("Interval must be a positive value.")
         return False
    if args.cpu_threshold < 0 or args.cpu_threshold > 100:
        logging.error("CPU threshold must be between 0 and 100.")
        return False
    if args.mem_threshold < 0 or args.mem_threshold > 100:
        logging.error("Memory threshold must be between 0 and 100.")
        return False
    return True

def check_process_activity(args):
     """
     Checks for high resource usage in system processes based on provided arguments.
     """
     logging.info("Starting process monitoring...")
     try:
        while True:
            for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                 try:
                    if args.process_name and process.info['name'] != args.process_name:
                        continue
                    cpu_usage = process.info['cpu_percent']
                    mem_usage = process.info['memory_percent']
                    
                    if cpu_usage > args.cpu_threshold:
                         logging.warning(f"Process {process.info['name']} (PID: {process.info['pid']}) CPU usage: {cpu_usage:.2f}% exceeds threshold: {args.cpu_threshold:.2f}%")
                    
                    if mem_usage > args.mem_threshold:
                        logging.warning(f"Process {process.info['name']} (PID: {process.info['pid']}) Memory usage: {mem_usage:.2f}% exceeds threshold: {args.mem_threshold:.2f}%")
                 except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                     logging.error(f"Error accessing process info. {e}")
                     continue # Skip to next process on error
            time.sleep(args.interval)
     except KeyboardInterrupt:
        logging.info("Process monitoring stopped by user.")
     except Exception as e:
         logging.error(f"An error occurred: {e}")


def signal_handler(sig, frame):
    """
    Handles SIGINT (Ctrl+C) to gracefully exit the program.
    """
    logging.info("Received signal, stopping process monitoring...")
    sys.exit(0)


def main():
    """
    Main function to execute the process monitoring tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Setup log file handler
    file_handler = logging.FileHandler(args.log_file)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logging.getLogger().addHandler(file_handler)

    if not validate_args(args):
        sys.exit(1)

    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)

    check_process_activity(args)


if __name__ == "__main__":
    main()

# Usage examples:
# 1. Monitor all processes with default interval, CPU, and memory thresholds:
#    python main.py
#
# 2. Monitor processes every 30 seconds with a CPU threshold of 80% and a memory threshold of 70%:
#    python main.py --interval 30 --cpu_threshold 80 --mem_threshold 70
#
# 3. Monitor only processes named "chrome" with default thresholds:
#    python main.py --process_name chrome
#
# 4.  Monitor processes with a custom log file path:
#     python main.py --log_file custom_log.txt