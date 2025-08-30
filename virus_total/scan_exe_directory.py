
import os

def find_exe_files(directory):
	abs_directory = os.path.abspath(directory)
	exe_files = []
	for root, _, files in os.walk(abs_directory):
		for file in files:
			if file.lower().endswith('.exe'):
				exe_files.append(os.path.join(root, file))
	return exe_files
