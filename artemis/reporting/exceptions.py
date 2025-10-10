class TranslationNotFoundException(Exception):
    def __init__(self, message: str):
        self._message = message
        super().__init__(message)

    def __str__(self) -> str:
        return self._message


class PyBabelError(Exception):
    """Exception raised for errors related to pybabel operations."""
    
    def __init__(self, message: str, command=None, returncode=None, stdout=None, stderr=None):
        self.message = message
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(self.message)
    
    def __str__(self) -> str:
        error_msg = self.message
        if self.command:
            error_msg += f"\nCommand: {self.command}"
        if self.returncode is not None:
            error_msg += f"\nReturn code: {self.returncode}"
        if self.stderr:
            error_msg += f"\nError output: {self.stderr}"
        return error_msg
