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
		__declspec(dllimport) string();
		__declspec(dllimport) string(const char*);
		__declspec(dllimport) string(const string&);
		__declspec(dllimport) ~string();
		__declspec(dllimport) const string& operator=(const string&);

		__declspec(dllimport) int getLength();

		__declspec(dllimport) const string& operator+=(const string&);


		__declspec(dllimport) const string& operator+(const string&);
		__declspec(dllimport) const string& operator+(const char*);
		__declspec(dllimport) friend const string& operator+(const char*, const string&);

		__declspec(dllimport) friend ostream& operator<<(ostream&, ism::string&);
		__declspec(dllimport) friend istream& operator>>(istream&, ism::string&);


		__declspec(dllimport) bool operator!() const;
		__declspec(dllimport) char& operator[](int);
		__declspec(dllimport) const char& operator[](int) const;

		__declspec(dllimport) bool operator==(const string&) const;
		__declspec(dllimport) bool operator!=(const string&) const;
		__declspec(dllimport) bool operator<(const string&) const;
		__declspec(dllimport) bool operator>(const string&) const;
		__declspec(dllimport) bool operator<=(const string&) const;
		__declspec(dllimport) bool operator>=(const string&) const;

	}; //end class
}