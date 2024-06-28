class UserNotInList(Exception):
    def __init__(self, message: str = "User not in list") -> None:
        self.message = message
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message


class BudgetExceedLimit(Exception):
    def __init__(self, message: str = "Budget limit exceeded") -> None:
        self.message = message
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message


class ProjectAlreadyDeleted(Exception):
    def __init__(self, message: str = "Project has already been deleted") -> None:
        self.message = message
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message


class EntityAlreadyExists(Exception):
    def __init__(self, message: str = "Entity already exists") -> None:
        self.message = message
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message


class EntityNotFound(Exception):
    def __init__(self, message: str = "Entity not found") -> None:
        self.message = message
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message


class ForbiddenOperation(Exception):
    def __init__(self, message: str = "Forbidden operation") -> None:
        self.message = message
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message
