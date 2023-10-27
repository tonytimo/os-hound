import math

#TODO: move all of this to the test method class
class HelperFunctions:
    def __init__(self):
        pass

    def compute_gcd(self, a, b):
        """Compute the greatest common divisor of a and b."""
        while b:
            a, b = b, a % b
        return abs(a)

    def compute_gcd_list(self, numbers):
        """Compute the GCD of a list of numbers."""
        gcd_value = numbers[0]
        for number in numbers[1:]:
            gcd_value = self.compute_gcd(gcd_value, number)
        return gcd_value
