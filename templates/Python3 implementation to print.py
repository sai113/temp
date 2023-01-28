# Python3 implementation to print
# the counter clock wise
# spiral traversal of matrix
R = 4
C = 4

# Function to print
# the required traversal
def counterClockspiralPrint(m, n, arr) :
	k = 0; l = 0
	final=[]
	# k - starting row index
	# m - ending row index
	# l - starting column index
	# n - ending column index
	# i - iterator

	# initialize the count
	cnt = 0

	# total number of
	# elements in matrix
	total = m * n

	while (k < m and l < n) :
		if (cnt == total) :
			break

		# Print the first column
		# from the remaining columns
		for i in range(k, m) :
			print(arr[i][l], end = " ")
			cnt += 1
		
		l += 1

		if (cnt == total) :
			break

		# Print the last row from
		# the remaining rows
		for i in range (l, n) :
			print( arr[m - 1][i], end = " ")
			cnt += 1
		
		m -= 1
		
		if (cnt == total) :
			break

		# Print the last column
		# from the remaining columns
		if (k < m) :
			for i in range(m - 1, k - 1, -1) :
				final.append(arr[i][n - 1])
				cnt += 1
			n -= 1

		if (cnt == total) :
			break

		# Print the first row
		# from the remaining rows
		if (l < n) :
			for i in range(n - 1, l - 1, -1) :
				final.append( arr[k][i])
				cnt += 1
				
			k += 1
        print(final)
	#for i in range(0, len(final)):
    #     if i % 2:
    #        final2=final[i]
    #print(final2)



# Driver Code
arr = [ [ 1, 2, 3, 4 ],
		[ 5, 6, 7, 8 ],
		[ 9, 10, 11, 12 ],
		[ 13, 14, 15, 16 ] ]
		

temp=counterClockspiralPrint(R, C, arr)
for i in range(0, len(temp)):
    if i % 2:
        temp2=temp[i]
print(temp)



# This code is contributed by Nikita Tiwari
