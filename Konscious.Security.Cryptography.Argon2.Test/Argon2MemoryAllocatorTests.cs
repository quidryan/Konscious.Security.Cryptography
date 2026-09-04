namespace Konscious.Security.Cryptography
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using Xunit;

    public class Argon2MemoryAllocatorTests
    {
        /// <summary>
        /// A minimal pooling allocator: it reuses returned buffers, zeroes them (honoring the Rent contract),
        /// and records activity so tests can assert buffers are balanced and actually reused.
        /// </summary>
        private sealed class PoolingAllocator : IArgon2MemoryAllocator
        {
            private readonly Stack<ulong[]> _free = new Stack<ulong[]>();
            private int _outstanding;

            public int RentCount { get; private set; }
            public int ReturnCount { get; private set; }
            public int AllocationCount { get; private set; }
            public int MaxOutstanding { get; private set; }

            public ulong[] Rent(int minimumLength)
            {
                RentCount++;
                _outstanding++;
                if (_outstanding > MaxOutstanding)
                {
                    MaxOutstanding = _outstanding;
                }

                while (_free.Count > 0)
                {
                    var buf = _free.Pop();
                    if (buf.Length >= minimumLength)
                    {
                        Array.Clear(buf, 0, buf.Length); // Rent must return zeroed memory
                        return buf;
                    }
                }

                AllocationCount++;
                return new ulong[minimumLength];
            }

            public void Return(ulong[] buffer)
            {
                ReturnCount++;
                _outstanding--;
                Array.Clear(buffer, 0, buffer.Length);
                _free.Push(buffer);
            }
        }

        private static Argon2id NewHasher(byte[] password, IArgon2MemoryAllocator allocator = null)
        {
            var hasher = new Argon2id(password)
            {
                Salt = Encoding.UTF8.GetBytes("a fixed test salt"),
                DegreeOfParallelism = 2,
                MemorySize = 128,
                Iterations = 2,
            };

            if (allocator != null)
            {
                hasher.MemoryAllocator = allocator;
            }

            return hasher;
        }

        [Fact]
        public void CustomAllocatorProducesIdenticalHashAndReturnsEveryBuffer()
        {
            var password = Encoding.UTF8.GetBytes("correct horse battery staple");

            byte[] expected;
            using (var def = NewHasher(password))
            {
                expected = def.GetBytes(32);
            }

            var pool = new PoolingAllocator();
            byte[] pooled;
            using (var p = NewHasher(password, pool))
            {
                pooled = p.GetBytes(32);
            }

            Assert.Equal(expected, pooled);                 // identical output regardless of allocator
            Assert.Equal(pool.RentCount, pool.ReturnCount); // every rented buffer was returned
            Assert.True(pool.RentCount >= 2);               // at least one buffer per lane (DegreeOfParallelism)
        }

        [Fact]
        public void CustomAllocatorReusesBuffersAcrossHashes()
        {
            var password = Encoding.UTF8.GetBytes("correct horse battery staple");
            var pool = new PoolingAllocator();

            byte[] first = null;
            for (var i = 0; i < 3; i++)
            {
                using var p = NewHasher(password, pool);
                var result = p.GetBytes(32);
                first ??= result;
                Assert.Equal(first, result); // reused, cleared buffers still yield a stable hash
            }

            Assert.Equal(pool.RentCount, pool.ReturnCount);
            // Buffers are returned between sequential hashes, so the pool never allocates more than the peak
            // number outstanding at once — everything past that is a reuse.
            Assert.Equal(pool.MaxOutstanding, pool.AllocationCount);
            Assert.True(pool.RentCount > pool.AllocationCount);
        }
    }
}
