#ifndef _LINKLIST_H
#define _LINKLIST_H

typedef struct _NODE {
  struct _NODE    *pPrev;
  struct _NODE    *pNext;
  void  *pData;
} NODE,  *LPNODE;

class CLinkedList {
private:
  LPNODE   Find(void  *pData);
  LPNODE   pHead;
  LPNODE   pTail;
  LPNODE   pCurPosition;

public:
   CLinkedList();  
   ~CLinkedList();  
   void *GetFirst();  
   void *GetLast();  
   void *GetNext();  
   void *GetNext(void  *pData);  
   void *GetPrev( );  
   void *GetPrev(void  *pData);  
   void Add(void  *pData);  
   void Insert(void  *pData);  
   void Insert(void *pData, void  *pBefore);  
   void Append(void  *pData);  
   void Remove( );  
   void Remove(void  *pData);  
   void *RemoveFirst();  
   void *RemoveLast();
   int IsEmpty();
   void SetCurToTail();
   void *GetCurrent();
};

#define LinkedList  CLinkedList

#endif
