#include <iostream>
#include <string>
using namespace std;

namespace ism
{
	class string
	{
	private:
		int length;
		char* ps;
	public:
		string();
		string(const char*);
		string(const string&);
		~string();
		const string& operator=(const string&);

		int getLength();

		const string& operator+=(const string&);

		//concatenation
		const string& operator+(const string&);
		const string& operator+(const char*);
		friend const string& operator+(const char*, const string&);

		friend ostream& operator<<(ostream&, ism::string&);
		friend istream& operator>>(istream&, ism::string&);

		//overloading unary operators 
		bool operator!() const; //test the string is empty
		char& operator[](int);
		const char& operator[](int) const;

		//overloading binary operators 
		bool operator==(const string&) const;
		bool operator!=(const string&) const;
		bool operator<(const string&) const;
		bool operator>(const string&) const;
		bool operator<=(const string&) const;
		bool operator>=(const string&) const;

	}; //end class
}